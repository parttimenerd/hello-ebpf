/** Auto-generated */
package me.bechberger.ebpf.runtime;

import me.bechberger.ebpf.annotations.EnumMember;
import me.bechberger.ebpf.annotations.InlineUnion;
import me.bechberger.ebpf.annotations.Offset;
import me.bechberger.ebpf.annotations.OriginalName;
import me.bechberger.ebpf.annotations.Size;
import me.bechberger.ebpf.annotations.Type;
import me.bechberger.ebpf.annotations.Unsigned;
import me.bechberger.ebpf.annotations.bpf.BuiltinBPFFunction;
import me.bechberger.ebpf.annotations.bpf.MethodIsBPFRelatedFunction;
import me.bechberger.ebpf.annotations.bpf.NotUsableInJava;
import me.bechberger.ebpf.type.Enum;
import me.bechberger.ebpf.type.Ptr;
import me.bechberger.ebpf.type.Struct;
import me.bechberger.ebpf.type.TypedEnum;
import me.bechberger.ebpf.type.TypedefBase;
import me.bechberger.ebpf.type.Union;
import org.jetbrains.annotations.Nullable;
import static me.bechberger.ebpf.runtime.AaDefinitions.*;
import static me.bechberger.ebpf.runtime.AafsDefinitions.*;
import static me.bechberger.ebpf.runtime.Aat2870Definitions.*;
import static me.bechberger.ebpf.runtime.AccountDefinitions.*;
import static me.bechberger.ebpf.runtime.AcctDefinitions.*;
import static me.bechberger.ebpf.runtime.AcompDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiDefinitions.*;
import static me.bechberger.ebpf.runtime.AcpiphpDefinitions.*;
import static me.bechberger.ebpf.runtime.ActionDefinitions.*;
import static me.bechberger.ebpf.runtime.ActiveDefinitions.*;
import static me.bechberger.ebpf.runtime.AddDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrDefinitions.*;
import static me.bechberger.ebpf.runtime.AddrconfDefinitions.*;
import static me.bechberger.ebpf.runtime.AdjustDefinitions.*;
import static me.bechberger.ebpf.runtime.AdlDefinitions.*;
import static me.bechberger.ebpf.runtime.Adp5520Definitions.*;
import static me.bechberger.ebpf.runtime.AdvisorDefinitions.*;
import static me.bechberger.ebpf.runtime.AeadDefinitions.*;
import static me.bechberger.ebpf.runtime.AerDefinitions.*;
import static me.bechberger.ebpf.runtime.AgpDefinitions.*;
import static me.bechberger.ebpf.runtime.AhashDefinitions.*;
import static me.bechberger.ebpf.runtime.AioDefinitions.*;
import static me.bechberger.ebpf.runtime.AlarmDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocDefinitions.*;
import static me.bechberger.ebpf.runtime.AllocateDefinitions.*;
import static me.bechberger.ebpf.runtime.AmdDefinitions.*;
import static me.bechberger.ebpf.runtime.AmlDefinitions.*;
import static me.bechberger.ebpf.runtime.AnonDefinitions.*;
import static me.bechberger.ebpf.runtime.ApeiDefinitions.*;
import static me.bechberger.ebpf.runtime.ApicDefinitions.*;
import static me.bechberger.ebpf.runtime.ApparmorDefinitions.*;
import static me.bechberger.ebpf.runtime.AppendDefinitions.*;
import static me.bechberger.ebpf.runtime.ApplyDefinitions.*;
import static me.bechberger.ebpf.runtime.ArchDefinitions.*;
import static me.bechberger.ebpf.runtime.ArenaDefinitions.*;
import static me.bechberger.ebpf.runtime.ArpDefinitions.*;
import static me.bechberger.ebpf.runtime.ArrayDefinitions.*;
import static me.bechberger.ebpf.runtime.Asn1Definitions.*;
import static me.bechberger.ebpf.runtime.AssocDefinitions.*;
import static me.bechberger.ebpf.runtime.AsymmetricDefinitions.*;
import static me.bechberger.ebpf.runtime.AsyncDefinitions.*;
import static me.bechberger.ebpf.runtime.AtaDefinitions.*;
import static me.bechberger.ebpf.runtime.AtkbdDefinitions.*;
import static me.bechberger.ebpf.runtime.AtomicDefinitions.*;
import static me.bechberger.ebpf.runtime.AttachDefinitions.*;
import static me.bechberger.ebpf.runtime.AttributeDefinitions.*;
import static me.bechberger.ebpf.runtime.AuditDefinitions.*;
import static me.bechberger.ebpf.runtime.AuxiliaryDefinitions.*;
import static me.bechberger.ebpf.runtime.AvailableDefinitions.*;
import static me.bechberger.ebpf.runtime.AvcDefinitions.*;
import static me.bechberger.ebpf.runtime.AvtabDefinitions.*;
import static me.bechberger.ebpf.runtime.BackingDefinitions.*;
import static me.bechberger.ebpf.runtime.BacklightDefinitions.*;
import static me.bechberger.ebpf.runtime.BadDefinitions.*;
import static me.bechberger.ebpf.runtime.BadblocksDefinitions.*;
import static me.bechberger.ebpf.runtime.BalanceDefinitions.*;
import static me.bechberger.ebpf.runtime.BalloonDefinitions.*;
import static me.bechberger.ebpf.runtime.BdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BdiDefinitions.*;
import static me.bechberger.ebpf.runtime.BgpioDefinitions.*;
import static me.bechberger.ebpf.runtime.BhDefinitions.*;
import static me.bechberger.ebpf.runtime.BindDefinitions.*;
import static me.bechberger.ebpf.runtime.BioDefinitions.*;
import static me.bechberger.ebpf.runtime.BitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.Blake2sDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkcgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkdevDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkgDefinitions.*;
import static me.bechberger.ebpf.runtime.BlkifDefinitions.*;
import static me.bechberger.ebpf.runtime.BlockDefinitions.*;
import static me.bechberger.ebpf.runtime.BloomDefinitions.*;
import static me.bechberger.ebpf.runtime.BootDefinitions.*;
import static me.bechberger.ebpf.runtime.BpfDefinitions.*;
import static me.bechberger.ebpf.runtime.BqlDefinitions.*;
import static me.bechberger.ebpf.runtime.BsgDefinitions.*;
import static me.bechberger.ebpf.runtime.BtfDefinitions.*;
import static me.bechberger.ebpf.runtime.BtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.BtsDefinitions.*;
import static me.bechberger.ebpf.runtime.BufferDefinitions.*;
import static me.bechberger.ebpf.runtime.BuildDefinitions.*;
import static me.bechberger.ebpf.runtime.BusDefinitions.*;
import static me.bechberger.ebpf.runtime.BytDefinitions.*;
import static me.bechberger.ebpf.runtime.CacheDefinitions.*;
import static me.bechberger.ebpf.runtime.CalcDefinitions.*;
import static me.bechberger.ebpf.runtime.CalculateDefinitions.*;
import static me.bechberger.ebpf.runtime.CalipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.CallDefinitions.*;
import static me.bechberger.ebpf.runtime.CanDefinitions.*;
import static me.bechberger.ebpf.runtime.CapDefinitions.*;
import static me.bechberger.ebpf.runtime.CcDefinitions.*;
import static me.bechberger.ebpf.runtime.CdevDefinitions.*;
import static me.bechberger.ebpf.runtime.CdromDefinitions.*;
import static me.bechberger.ebpf.runtime.CeaDefinitions.*;
import static me.bechberger.ebpf.runtime.Cfg80211Definitions.*;
import static me.bechberger.ebpf.runtime.Cgroup1Definitions.*;
import static me.bechberger.ebpf.runtime.CgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ChangeDefinitions.*;
import static me.bechberger.ebpf.runtime.ChargerDefinitions.*;
import static me.bechberger.ebpf.runtime.CheckDefinitions.*;
import static me.bechberger.ebpf.runtime.ChvDefinitions.*;
import static me.bechberger.ebpf.runtime.CipsoDefinitions.*;
import static me.bechberger.ebpf.runtime.ClassDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanDefinitions.*;
import static me.bechberger.ebpf.runtime.CleanupDefinitions.*;
import static me.bechberger.ebpf.runtime.ClearDefinitions.*;
import static me.bechberger.ebpf.runtime.ClkDefinitions.*;
import static me.bechberger.ebpf.runtime.ClockeventsDefinitions.*;
import static me.bechberger.ebpf.runtime.ClocksourceDefinitions.*;
import static me.bechberger.ebpf.runtime.ClosureDefinitions.*;
import static me.bechberger.ebpf.runtime.CmaDefinitions.*;
import static me.bechberger.ebpf.runtime.CmciDefinitions.*;
import static me.bechberger.ebpf.runtime.CmdlineDefinitions.*;
import static me.bechberger.ebpf.runtime.CmisDefinitions.*;
import static me.bechberger.ebpf.runtime.CmosDefinitions.*;
import static me.bechberger.ebpf.runtime.CmpDefinitions.*;
import static me.bechberger.ebpf.runtime.CnDefinitions.*;
import static me.bechberger.ebpf.runtime.CollapseDefinitions.*;
import static me.bechberger.ebpf.runtime.CollectDefinitions.*;
import static me.bechberger.ebpf.runtime.CommonDefinitions.*;
import static me.bechberger.ebpf.runtime.CompactionDefinitions.*;
import static me.bechberger.ebpf.runtime.CompatDefinitions.*;
import static me.bechberger.ebpf.runtime.ComponentDefinitions.*;
import static me.bechberger.ebpf.runtime.ComputeDefinitions.*;
import static me.bechberger.ebpf.runtime.ConDefinitions.*;
import static me.bechberger.ebpf.runtime.CondDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigDefinitions.*;
import static me.bechberger.ebpf.runtime.ConfigfsDefinitions.*;
import static me.bechberger.ebpf.runtime.ConsoleDefinitions.*;
import static me.bechberger.ebpf.runtime.ContextDefinitions.*;
import static me.bechberger.ebpf.runtime.ConvertDefinitions.*;
import static me.bechberger.ebpf.runtime.CookieDefinitions.*;
import static me.bechberger.ebpf.runtime.CopyDefinitions.*;
import static me.bechberger.ebpf.runtime.CoreDefinitions.*;
import static me.bechberger.ebpf.runtime.CoredumpDefinitions.*;
import static me.bechberger.ebpf.runtime.CountDefinitions.*;
import static me.bechberger.ebpf.runtime.CpciDefinitions.*;
import static me.bechberger.ebpf.runtime.CperDefinitions.*;
import static me.bechberger.ebpf.runtime.CppcDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuacctDefinitions.*;
import static me.bechberger.ebpf.runtime.CpufreqDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuhpDefinitions.*;
import static me.bechberger.ebpf.runtime.CpuidleDefinitions.*;
import static me.bechberger.ebpf.runtime.CpumaskDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusDefinitions.*;
import static me.bechberger.ebpf.runtime.CpusetDefinitions.*;
import static me.bechberger.ebpf.runtime.CrashDefinitions.*;
import static me.bechberger.ebpf.runtime.CrbDefinitions.*;
import static me.bechberger.ebpf.runtime.Crc64Definitions.*;
import static me.bechberger.ebpf.runtime.CreateDefinitions.*;
import static me.bechberger.ebpf.runtime.CryptoDefinitions.*;
import static me.bechberger.ebpf.runtime.CrystalcoveDefinitions.*;
import static me.bechberger.ebpf.runtime.CssDefinitions.*;
import static me.bechberger.ebpf.runtime.CsumDefinitions.*;
import static me.bechberger.ebpf.runtime.CtDefinitions.*;
import static me.bechberger.ebpf.runtime.CtrlDefinitions.*;
import static me.bechberger.ebpf.runtime.CtxDefinitions.*;
import static me.bechberger.ebpf.runtime.CurrentDefinitions.*;
import static me.bechberger.ebpf.runtime.CxlDefinitions.*;
import static me.bechberger.ebpf.runtime.DDefinitions.*;
import static me.bechberger.ebpf.runtime.Da903xDefinitions.*;
import static me.bechberger.ebpf.runtime.Da9052Definitions.*;
import static me.bechberger.ebpf.runtime.Da9063Definitions.*;
import static me.bechberger.ebpf.runtime.DataDefinitions.*;
import static me.bechberger.ebpf.runtime.DaxDefinitions.*;
import static me.bechberger.ebpf.runtime.DbcDefinitions.*;
import static me.bechberger.ebpf.runtime.DbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbDefinitions.*;
import static me.bechberger.ebpf.runtime.DcbnlDefinitions.*;
import static me.bechberger.ebpf.runtime.DdDefinitions.*;
import static me.bechberger.ebpf.runtime.DdebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DeadlineDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugDefinitions.*;
import static me.bechberger.ebpf.runtime.DebugfsDefinitions.*;
import static me.bechberger.ebpf.runtime.DecDefinitions.*;
import static me.bechberger.ebpf.runtime.DefaultDefinitions.*;
import static me.bechberger.ebpf.runtime.DeferredDefinitions.*;
import static me.bechberger.ebpf.runtime.DeflateDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayacctDefinitions.*;
import static me.bechberger.ebpf.runtime.DelayedDefinitions.*;
import static me.bechberger.ebpf.runtime.DeleteDefinitions.*;
import static me.bechberger.ebpf.runtime.DentryDefinitions.*;
import static me.bechberger.ebpf.runtime.DequeueDefinitions.*;
import static me.bechberger.ebpf.runtime.DescDefinitions.*;
import static me.bechberger.ebpf.runtime.DestroyDefinitions.*;
import static me.bechberger.ebpf.runtime.DetachDefinitions.*;
import static me.bechberger.ebpf.runtime.DevDefinitions.*;
import static me.bechberger.ebpf.runtime.DevcdDefinitions.*;
import static me.bechberger.ebpf.runtime.DevfreqDefinitions.*;
import static me.bechberger.ebpf.runtime.DeviceDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlDefinitions.*;
import static me.bechberger.ebpf.runtime.DevlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.DevmDefinitions.*;
import static me.bechberger.ebpf.runtime.DevptsDefinitions.*;
import static me.bechberger.ebpf.runtime.DevresDefinitions.*;
import static me.bechberger.ebpf.runtime.DhDefinitions.*;
import static me.bechberger.ebpf.runtime.DimDefinitions.*;
import static me.bechberger.ebpf.runtime.DisableDefinitions.*;
import static me.bechberger.ebpf.runtime.DiskDefinitions.*;
import static me.bechberger.ebpf.runtime.DispatchDefinitions.*;
import static me.bechberger.ebpf.runtime.DisplayidDefinitions.*;
import static me.bechberger.ebpf.runtime.DlDefinitions.*;
import static me.bechberger.ebpf.runtime.DmDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaDefinitions.*;
import static me.bechberger.ebpf.runtime.DmabufDefinitions.*;
import static me.bechberger.ebpf.runtime.DmaengineDefinitions.*;
import static me.bechberger.ebpf.runtime.DmarDefinitions.*;
import static me.bechberger.ebpf.runtime.DmemDefinitions.*;
import static me.bechberger.ebpf.runtime.DmiDefinitions.*;
import static me.bechberger.ebpf.runtime.DnsDefinitions.*;
import static me.bechberger.ebpf.runtime.DoDefinitions.*;
import static me.bechberger.ebpf.runtime.DomainDefinitions.*;
import static me.bechberger.ebpf.runtime.DownDefinitions.*;
import static me.bechberger.ebpf.runtime.DpcDefinitions.*;
import static me.bechberger.ebpf.runtime.DpllDefinitions.*;
import static me.bechberger.ebpf.runtime.DpmDefinitions.*;
import static me.bechberger.ebpf.runtime.DquotDefinitions.*;
import static me.bechberger.ebpf.runtime.DrainDefinitions.*;
import static me.bechberger.ebpf.runtime.DrbgDefinitions.*;
import static me.bechberger.ebpf.runtime.DriverDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmDefinitions.*;
import static me.bechberger.ebpf.runtime.DrmmDefinitions.*;
import static me.bechberger.ebpf.runtime.DropDefinitions.*;
import static me.bechberger.ebpf.runtime.DsaDefinitions.*;
import static me.bechberger.ebpf.runtime.DstDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyDefinitions.*;
import static me.bechberger.ebpf.runtime.DummyconDefinitions.*;
import static me.bechberger.ebpf.runtime.DumpDefinitions.*;
import static me.bechberger.ebpf.runtime.DupDefinitions.*;
import static me.bechberger.ebpf.runtime.DvdDefinitions.*;
import static me.bechberger.ebpf.runtime.DwDefinitions.*;
import static me.bechberger.ebpf.runtime.Dwc2Definitions.*;
import static me.bechberger.ebpf.runtime.DxDefinitions.*;
import static me.bechberger.ebpf.runtime.DynDefinitions.*;
import static me.bechberger.ebpf.runtime.DyneventDefinitions.*;
import static me.bechberger.ebpf.runtime.EafnosupportDefinitions.*;
import static me.bechberger.ebpf.runtime.EarlyDefinitions.*;
import static me.bechberger.ebpf.runtime.EbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.EcDefinitions.*;
import static me.bechberger.ebpf.runtime.EccDefinitions.*;
import static me.bechberger.ebpf.runtime.EcryptfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EdacDefinitions.*;
import static me.bechberger.ebpf.runtime.EddDefinitions.*;
import static me.bechberger.ebpf.runtime.EdidDefinitions.*;
import static me.bechberger.ebpf.runtime.EfiDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarDefinitions.*;
import static me.bechberger.ebpf.runtime.EfivarfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EhciDefinitions.*;
import static me.bechberger.ebpf.runtime.ElantsDefinitions.*;
import static me.bechberger.ebpf.runtime.ElevatorDefinitions.*;
import static me.bechberger.ebpf.runtime.ElfDefinitions.*;
import static me.bechberger.ebpf.runtime.ElvDefinitions.*;
import static me.bechberger.ebpf.runtime.EmDefinitions.*;
import static me.bechberger.ebpf.runtime.EmitDefinitions.*;
import static me.bechberger.ebpf.runtime.EnableDefinitions.*;
import static me.bechberger.ebpf.runtime.EndDefinitions.*;
import static me.bechberger.ebpf.runtime.EnqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.EpDefinitions.*;
import static me.bechberger.ebpf.runtime.EprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.ErstDefinitions.*;
import static me.bechberger.ebpf.runtime.EspintcpDefinitions.*;
import static me.bechberger.ebpf.runtime.EthDefinitions.*;
import static me.bechberger.ebpf.runtime.EthnlDefinitions.*;
import static me.bechberger.ebpf.runtime.EthtoolDefinitions.*;
import static me.bechberger.ebpf.runtime.EvdevDefinitions.*;
import static me.bechberger.ebpf.runtime.EventDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfdDefinitions.*;
import static me.bechberger.ebpf.runtime.EventfsDefinitions.*;
import static me.bechberger.ebpf.runtime.EvmDefinitions.*;
import static me.bechberger.ebpf.runtime.EvtchnDefinitions.*;
import static me.bechberger.ebpf.runtime.ExcDefinitions.*;
import static me.bechberger.ebpf.runtime.ExecmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ExitDefinitions.*;
import static me.bechberger.ebpf.runtime.Ext4Definitions.*;
import static me.bechberger.ebpf.runtime.ExtconDefinitions.*;
import static me.bechberger.ebpf.runtime.FDefinitions.*;
import static me.bechberger.ebpf.runtime.FanotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FatDefinitions.*;
import static me.bechberger.ebpf.runtime.FaultDefinitions.*;
import static me.bechberger.ebpf.runtime.FauxDefinitions.*;
import static me.bechberger.ebpf.runtime.FbDefinitions.*;
import static me.bechberger.ebpf.runtime.FbconDefinitions.*;
import static me.bechberger.ebpf.runtime.FdtDefinitions.*;
import static me.bechberger.ebpf.runtime.FfDefinitions.*;
import static me.bechberger.ebpf.runtime.FgraphDefinitions.*;
import static me.bechberger.ebpf.runtime.Fib4Definitions.*;
import static me.bechberger.ebpf.runtime.Fib6Definitions.*;
import static me.bechberger.ebpf.runtime.FibDefinitions.*;
import static me.bechberger.ebpf.runtime.FifoDefinitions.*;
import static me.bechberger.ebpf.runtime.FileDefinitions.*;
import static me.bechberger.ebpf.runtime.FilemapDefinitions.*;
import static me.bechberger.ebpf.runtime.FilenameDefinitions.*;
import static me.bechberger.ebpf.runtime.FillDefinitions.*;
import static me.bechberger.ebpf.runtime.FilterDefinitions.*;
import static me.bechberger.ebpf.runtime.FindDefinitions.*;
import static me.bechberger.ebpf.runtime.FinishDefinitions.*;
import static me.bechberger.ebpf.runtime.FirmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.FixedDefinitions.*;
import static me.bechberger.ebpf.runtime.FixupDefinitions.*;
import static me.bechberger.ebpf.runtime.FlowDefinitions.*;
import static me.bechberger.ebpf.runtime.FlushDefinitions.*;
import static me.bechberger.ebpf.runtime.FnDefinitions.*;
import static me.bechberger.ebpf.runtime.FolioDefinitions.*;
import static me.bechberger.ebpf.runtime.FollowDefinitions.*;
import static me.bechberger.ebpf.runtime.FopsDefinitions.*;
import static me.bechberger.ebpf.runtime.ForDefinitions.*;
import static me.bechberger.ebpf.runtime.ForceDefinitions.*;
import static me.bechberger.ebpf.runtime.FprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.FpuDefinitions.*;
import static me.bechberger.ebpf.runtime.FredDefinitions.*;
import static me.bechberger.ebpf.runtime.FreeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezeDefinitions.*;
import static me.bechberger.ebpf.runtime.FreezerDefinitions.*;
import static me.bechberger.ebpf.runtime.FreqDefinitions.*;
import static me.bechberger.ebpf.runtime.FromDefinitions.*;
import static me.bechberger.ebpf.runtime.FsDefinitions.*;
import static me.bechberger.ebpf.runtime.FscryptDefinitions.*;
import static me.bechberger.ebpf.runtime.FseDefinitions.*;
import static me.bechberger.ebpf.runtime.FsnotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.FsverityDefinitions.*;
import static me.bechberger.ebpf.runtime.FtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.FullDefinitions.*;
import static me.bechberger.ebpf.runtime.FunctionDefinitions.*;
import static me.bechberger.ebpf.runtime.FuseDefinitions.*;
import static me.bechberger.ebpf.runtime.FutexDefinitions.*;
import static me.bechberger.ebpf.runtime.FwDefinitions.*;
import static me.bechberger.ebpf.runtime.FwnodeDefinitions.*;
import static me.bechberger.ebpf.runtime.GartDefinitions.*;
import static me.bechberger.ebpf.runtime.GcmDefinitions.*;
import static me.bechberger.ebpf.runtime.GenDefinitions.*;
import static me.bechberger.ebpf.runtime.GenericDefinitions.*;
import static me.bechberger.ebpf.runtime.GenlDefinitions.*;
import static me.bechberger.ebpf.runtime.GenpdDefinitions.*;
import static me.bechberger.ebpf.runtime.GenphyDefinitions.*;
import static me.bechberger.ebpf.runtime.GetDefinitions.*;
import static me.bechberger.ebpf.runtime.GhesDefinitions.*;
import static me.bechberger.ebpf.runtime.GnetDefinitions.*;
import static me.bechberger.ebpf.runtime.GnttabDefinitions.*;
import static me.bechberger.ebpf.runtime.GpioDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiochipDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiodDefinitions.*;
import static me.bechberger.ebpf.runtime.GpiolibDefinitions.*;
import static me.bechberger.ebpf.runtime.GroDefinitions.*;
import static me.bechberger.ebpf.runtime.GroupDefinitions.*;
import static me.bechberger.ebpf.runtime.GupDefinitions.*;
import static me.bechberger.ebpf.runtime.HandleDefinitions.*;
import static me.bechberger.ebpf.runtime.HandshakeDefinitions.*;
import static me.bechberger.ebpf.runtime.HasDefinitions.*;
import static me.bechberger.ebpf.runtime.HashDefinitions.*;
import static me.bechberger.ebpf.runtime.HcdDefinitions.*;
import static me.bechberger.ebpf.runtime.HctxDefinitions.*;
import static me.bechberger.ebpf.runtime.HdmiDefinitions.*;
import static me.bechberger.ebpf.runtime.HfiDefinitions.*;
import static me.bechberger.ebpf.runtime.HidDefinitions.*;
import static me.bechberger.ebpf.runtime.HistDefinitions.*;
import static me.bechberger.ebpf.runtime.HmacDefinitions.*;
import static me.bechberger.ebpf.runtime.HmatDefinitions.*;
import static me.bechberger.ebpf.runtime.HmmDefinitions.*;
import static me.bechberger.ebpf.runtime.HookDefinitions.*;
import static me.bechberger.ebpf.runtime.HpetDefinitions.*;
import static me.bechberger.ebpf.runtime.HrtimerDefinitions.*;
import static me.bechberger.ebpf.runtime.HsuDefinitions.*;
import static me.bechberger.ebpf.runtime.HswepDefinitions.*;
import static me.bechberger.ebpf.runtime.HtabDefinitions.*;
import static me.bechberger.ebpf.runtime.HteDefinitions.*;
import static me.bechberger.ebpf.runtime.HubDefinitions.*;
import static me.bechberger.ebpf.runtime.HufDefinitions.*;
import static me.bechberger.ebpf.runtime.HugepageDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbDefinitions.*;
import static me.bechberger.ebpf.runtime.HugetlbfsDefinitions.*;
import static me.bechberger.ebpf.runtime.HvDefinitions.*;
import static me.bechberger.ebpf.runtime.HvcDefinitions.*;
import static me.bechberger.ebpf.runtime.HwDefinitions.*;
import static me.bechberger.ebpf.runtime.HwlatDefinitions.*;
import static me.bechberger.ebpf.runtime.HwmonDefinitions.*;
import static me.bechberger.ebpf.runtime.HybridDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervDefinitions.*;
import static me.bechberger.ebpf.runtime.HypervisorDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cDefinitions.*;
import static me.bechberger.ebpf.runtime.I2cdevDefinitions.*;
import static me.bechberger.ebpf.runtime.I8042Definitions.*;
import static me.bechberger.ebpf.runtime.Ia32Definitions.*;
import static me.bechberger.ebpf.runtime.IbDefinitions.*;
import static me.bechberger.ebpf.runtime.IccDefinitions.*;
import static me.bechberger.ebpf.runtime.IcmpDefinitions.*;
import static me.bechberger.ebpf.runtime.Icmpv6Definitions.*;
import static me.bechberger.ebpf.runtime.IcxDefinitions.*;
import static me.bechberger.ebpf.runtime.IdleDefinitions.*;
import static me.bechberger.ebpf.runtime.IdrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ieee80211Definitions.*;
import static me.bechberger.ebpf.runtime.IflaDefinitions.*;
import static me.bechberger.ebpf.runtime.Igmp6Definitions.*;
import static me.bechberger.ebpf.runtime.IgmpDefinitions.*;
import static me.bechberger.ebpf.runtime.ImaDefinitions.*;
import static me.bechberger.ebpf.runtime.ImsttfbDefinitions.*;
import static me.bechberger.ebpf.runtime.In6Definitions.*;
import static me.bechberger.ebpf.runtime.InDefinitions.*;
import static me.bechberger.ebpf.runtime.IncDefinitions.*;
import static me.bechberger.ebpf.runtime.Inet6Definitions.*;
import static me.bechberger.ebpf.runtime.InetDefinitions.*;
import static me.bechberger.ebpf.runtime.InitDefinitions.*;
import static me.bechberger.ebpf.runtime.InodeDefinitions.*;
import static me.bechberger.ebpf.runtime.InotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.InputDefinitions.*;
import static me.bechberger.ebpf.runtime.InsertDefinitions.*;
import static me.bechberger.ebpf.runtime.InsnDefinitions.*;
import static me.bechberger.ebpf.runtime.IntDefinitions.*;
import static me.bechberger.ebpf.runtime.IntegrityDefinitions.*;
import static me.bechberger.ebpf.runtime.IntelDefinitions.*;
import static me.bechberger.ebpf.runtime.IntervalDefinitions.*;
import static me.bechberger.ebpf.runtime.InvalidateDefinitions.*;
import static me.bechberger.ebpf.runtime.IoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ioam6Definitions.*;
import static me.bechberger.ebpf.runtime.IoapicDefinitions.*;
import static me.bechberger.ebpf.runtime.IocDefinitions.*;
import static me.bechberger.ebpf.runtime.IocgDefinitions.*;
import static me.bechberger.ebpf.runtime.IoctlDefinitions.*;
import static me.bechberger.ebpf.runtime.IomapDefinitions.*;
import static me.bechberger.ebpf.runtime.IommuDefinitions.*;
import static me.bechberger.ebpf.runtime.IommufdDefinitions.*;
import static me.bechberger.ebpf.runtime.IopfDefinitions.*;
import static me.bechberger.ebpf.runtime.IoremapDefinitions.*;
import static me.bechberger.ebpf.runtime.IosfDefinitions.*;
import static me.bechberger.ebpf.runtime.IovDefinitions.*;
import static me.bechberger.ebpf.runtime.IovaDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip4Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6Definitions.*;
import static me.bechberger.ebpf.runtime.Ip6addrlblDefinitions.*;
import static me.bechberger.ebpf.runtime.Ip6mrDefinitions.*;
import static me.bechberger.ebpf.runtime.IpDefinitions.*;
import static me.bechberger.ebpf.runtime.IpcDefinitions.*;
import static me.bechberger.ebpf.runtime.IpeDefinitions.*;
import static me.bechberger.ebpf.runtime.IpmrDefinitions.*;
import static me.bechberger.ebpf.runtime.Ipv4Definitions.*;
import static me.bechberger.ebpf.runtime.Ipv6Definitions.*;
import static me.bechberger.ebpf.runtime.IrqDefinitions.*;
import static me.bechberger.ebpf.runtime.IrteDefinitions.*;
import static me.bechberger.ebpf.runtime.IsDefinitions.*;
import static me.bechberger.ebpf.runtime.IsaDefinitions.*;
import static me.bechberger.ebpf.runtime.IsolateDefinitions.*;
import static me.bechberger.ebpf.runtime.IterDefinitions.*;
import static me.bechberger.ebpf.runtime.IvbepDefinitions.*;
import static me.bechberger.ebpf.runtime.IwDefinitions.*;
import static me.bechberger.ebpf.runtime.JailhouseDefinitions.*;
import static me.bechberger.ebpf.runtime.Jbd2Definitions.*;
import static me.bechberger.ebpf.runtime.JentDefinitions.*;
import static me.bechberger.ebpf.runtime.JournalDefinitions.*;
import static me.bechberger.ebpf.runtime.JumpDefinitions.*;
import static me.bechberger.ebpf.runtime.KDefinitions.*;
import static me.bechberger.ebpf.runtime.KallsymsDefinitions.*;
import static me.bechberger.ebpf.runtime.KbdDefinitions.*;
import static me.bechberger.ebpf.runtime.KdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KernDefinitions.*;
import static me.bechberger.ebpf.runtime.KernelDefinitions.*;
import static me.bechberger.ebpf.runtime.KernfsDefinitions.*;
import static me.bechberger.ebpf.runtime.KexecDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyctlDefinitions.*;
import static me.bechberger.ebpf.runtime.KeyringDefinitions.*;
import static me.bechberger.ebpf.runtime.KfenceDefinitions.*;
import static me.bechberger.ebpf.runtime.KfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.KfreeDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbDefinitions.*;
import static me.bechberger.ebpf.runtime.KgdbocDefinitions.*;
import static me.bechberger.ebpf.runtime.KhoDefinitions.*;
import static me.bechberger.ebpf.runtime.KillDefinitions.*;
import static me.bechberger.ebpf.runtime.KimageDefinitions.*;
import static me.bechberger.ebpf.runtime.KlistDefinitions.*;
import static me.bechberger.ebpf.runtime.KlpDefinitions.*;
import static me.bechberger.ebpf.runtime.KmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.KmemDefinitions.*;
import static me.bechberger.ebpf.runtime.KmsgDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjDefinitions.*;
import static me.bechberger.ebpf.runtime.KobjectDefinitions.*;
import static me.bechberger.ebpf.runtime.KprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.KsmDefinitions.*;
import static me.bechberger.ebpf.runtime.KsysDefinitions.*;
import static me.bechberger.ebpf.runtime.KthreadDefinitions.*;
import static me.bechberger.ebpf.runtime.KtimeDefinitions.*;
import static me.bechberger.ebpf.runtime.KvmDefinitions.*;
import static me.bechberger.ebpf.runtime.L3mdevDefinitions.*;
import static me.bechberger.ebpf.runtime.LabelDefinitions.*;
import static me.bechberger.ebpf.runtime.LandlockDefinitions.*;
import static me.bechberger.ebpf.runtime.LapicDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmDefinitions.*;
import static me.bechberger.ebpf.runtime.LdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.LedDefinitions.*;
import static me.bechberger.ebpf.runtime.LedtrigDefinitions.*;
import static me.bechberger.ebpf.runtime.LegacyDefinitions.*;
import static me.bechberger.ebpf.runtime.LinearDefinitions.*;
import static me.bechberger.ebpf.runtime.LineeventDefinitions.*;
import static me.bechberger.ebpf.runtime.LinereqDefinitions.*;
import static me.bechberger.ebpf.runtime.LinkDefinitions.*;
import static me.bechberger.ebpf.runtime.LinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.ListDefinitions.*;
import static me.bechberger.ebpf.runtime.LoadDefinitions.*;
import static me.bechberger.ebpf.runtime.LocalDefinitions.*;
import static me.bechberger.ebpf.runtime.LockDefinitions.*;
import static me.bechberger.ebpf.runtime.LocksDefinitions.*;
import static me.bechberger.ebpf.runtime.LockupDefinitions.*;
import static me.bechberger.ebpf.runtime.LogDefinitions.*;
import static me.bechberger.ebpf.runtime.LookupDefinitions.*;
import static me.bechberger.ebpf.runtime.LoopDefinitions.*;
import static me.bechberger.ebpf.runtime.Lp8788Definitions.*;
import static me.bechberger.ebpf.runtime.LpssDefinitions.*;
import static me.bechberger.ebpf.runtime.LruDefinitions.*;
import static me.bechberger.ebpf.runtime.LskcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.LsmDefinitions.*;
import static me.bechberger.ebpf.runtime.LwtunnelDefinitions.*;
import static me.bechberger.ebpf.runtime.Lz4Definitions.*;
import static me.bechberger.ebpf.runtime.MachineDefinitions.*;
import static me.bechberger.ebpf.runtime.MacsecDefinitions.*;
import static me.bechberger.ebpf.runtime.MadviseDefinitions.*;
import static me.bechberger.ebpf.runtime.MakeDefinitions.*;
import static me.bechberger.ebpf.runtime.MapDefinitions.*;
import static me.bechberger.ebpf.runtime.MapleDefinitions.*;
import static me.bechberger.ebpf.runtime.MarkDefinitions.*;
import static me.bechberger.ebpf.runtime.MasDefinitions.*;
import static me.bechberger.ebpf.runtime.MatchDefinitions.*;
import static me.bechberger.ebpf.runtime.Max310xDefinitions.*;
import static me.bechberger.ebpf.runtime.Max77693Definitions.*;
import static me.bechberger.ebpf.runtime.Max8925Definitions.*;
import static me.bechberger.ebpf.runtime.Max8997Definitions.*;
import static me.bechberger.ebpf.runtime.Max8998Definitions.*;
import static me.bechberger.ebpf.runtime.MaxDefinitions.*;
import static me.bechberger.ebpf.runtime.MayDefinitions.*;
import static me.bechberger.ebpf.runtime.MaybeDefinitions.*;
import static me.bechberger.ebpf.runtime.MbDefinitions.*;
import static me.bechberger.ebpf.runtime.MbmDefinitions.*;
import static me.bechberger.ebpf.runtime.MboxDefinitions.*;
import static me.bechberger.ebpf.runtime.MceDefinitions.*;
import static me.bechberger.ebpf.runtime.McheckDefinitions.*;
import static me.bechberger.ebpf.runtime.MciDefinitions.*;
import static me.bechberger.ebpf.runtime.MctpDefinitions.*;
import static me.bechberger.ebpf.runtime.MctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.MdDefinitions.*;
import static me.bechberger.ebpf.runtime.MddevDefinitions.*;
import static me.bechberger.ebpf.runtime.MdioDefinitions.*;
import static me.bechberger.ebpf.runtime.MdiobusDefinitions.*;
import static me.bechberger.ebpf.runtime.MemDefinitions.*;
import static me.bechberger.ebpf.runtime.MemblockDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcgDefinitions.*;
import static me.bechberger.ebpf.runtime.MemcpyDefinitions.*;
import static me.bechberger.ebpf.runtime.MemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MemoryDefinitions.*;
import static me.bechberger.ebpf.runtime.MempoolDefinitions.*;
import static me.bechberger.ebpf.runtime.MemtypeDefinitions.*;
import static me.bechberger.ebpf.runtime.MigrateDefinitions.*;
import static me.bechberger.ebpf.runtime.MinDefinitions.*;
import static me.bechberger.ebpf.runtime.MipiDefinitions.*;
import static me.bechberger.ebpf.runtime.MiscDefinitions.*;
import static me.bechberger.ebpf.runtime.MldDefinitions.*;
import static me.bechberger.ebpf.runtime.MlsDefinitions.*;
import static me.bechberger.ebpf.runtime.MmDefinitions.*;
import static me.bechberger.ebpf.runtime.MmapDefinitions.*;
import static me.bechberger.ebpf.runtime.MmcDefinitions.*;
import static me.bechberger.ebpf.runtime.MmioDefinitions.*;
import static me.bechberger.ebpf.runtime.MmuDefinitions.*;
import static me.bechberger.ebpf.runtime.MntDefinitions.*;
import static me.bechberger.ebpf.runtime.ModDefinitions.*;
import static me.bechberger.ebpf.runtime.ModuleDefinitions.*;
import static me.bechberger.ebpf.runtime.MountDefinitions.*;
import static me.bechberger.ebpf.runtime.MousedevDefinitions.*;
import static me.bechberger.ebpf.runtime.MoveDefinitions.*;
import static me.bechberger.ebpf.runtime.MpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpageDefinitions.*;
import static me.bechberger.ebpf.runtime.MpiDefinitions.*;
import static me.bechberger.ebpf.runtime.MpihelpDefinitions.*;
import static me.bechberger.ebpf.runtime.MpolDefinitions.*;
import static me.bechberger.ebpf.runtime.MptcpDefinitions.*;
import static me.bechberger.ebpf.runtime.MqDefinitions.*;
import static me.bechberger.ebpf.runtime.MqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.MrDefinitions.*;
import static me.bechberger.ebpf.runtime.MsgDefinitions.*;
import static me.bechberger.ebpf.runtime.MsiDefinitions.*;
import static me.bechberger.ebpf.runtime.MsrDefinitions.*;
import static me.bechberger.ebpf.runtime.MtDefinitions.*;
import static me.bechberger.ebpf.runtime.MtreeDefinitions.*;
import static me.bechberger.ebpf.runtime.MtrrDefinitions.*;
import static me.bechberger.ebpf.runtime.MutexDefinitions.*;
import static me.bechberger.ebpf.runtime.NDefinitions.*;
import static me.bechberger.ebpf.runtime.NapiDefinitions.*;
import static me.bechberger.ebpf.runtime.NativeDefinitions.*;
import static me.bechberger.ebpf.runtime.NbconDefinitions.*;
import static me.bechberger.ebpf.runtime.NcsiDefinitions.*;
import static me.bechberger.ebpf.runtime.NdDefinitions.*;
import static me.bechberger.ebpf.runtime.NdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.NeighDefinitions.*;
import static me.bechberger.ebpf.runtime.NetDefinitions.*;
import static me.bechberger.ebpf.runtime.NetdevDefinitions.*;
import static me.bechberger.ebpf.runtime.NetifDefinitions.*;
import static me.bechberger.ebpf.runtime.NetkitDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlblDefinitions.*;
import static me.bechberger.ebpf.runtime.NetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.NetnsDefinitions.*;
import static me.bechberger.ebpf.runtime.NetpollDefinitions.*;
import static me.bechberger.ebpf.runtime.NewDefinitions.*;
import static me.bechberger.ebpf.runtime.NextDefinitions.*;
import static me.bechberger.ebpf.runtime.NexthopDefinitions.*;
import static me.bechberger.ebpf.runtime.NfDefinitions.*;
import static me.bechberger.ebpf.runtime.Nfs4Definitions.*;
import static me.bechberger.ebpf.runtime.NfsDefinitions.*;
import static me.bechberger.ebpf.runtime.NhDefinitions.*;
import static me.bechberger.ebpf.runtime.NhmexDefinitions.*;
import static me.bechberger.ebpf.runtime.Nl80211Definitions.*;
import static me.bechberger.ebpf.runtime.NlaDefinitions.*;
import static me.bechberger.ebpf.runtime.NmiDefinitions.*;
import static me.bechberger.ebpf.runtime.NoDefinitions.*;
import static me.bechberger.ebpf.runtime.NodeDefinitions.*;
import static me.bechberger.ebpf.runtime.NoopDefinitions.*;
import static me.bechberger.ebpf.runtime.NotifyDefinitions.*;
import static me.bechberger.ebpf.runtime.NrDefinitions.*;
import static me.bechberger.ebpf.runtime.NsDefinitions.*;
import static me.bechberger.ebpf.runtime.NullDefinitions.*;
import static me.bechberger.ebpf.runtime.NumaDefinitions.*;
import static me.bechberger.ebpf.runtime.NumachipDefinitions.*;
import static me.bechberger.ebpf.runtime.NvdimmDefinitions.*;
import static me.bechberger.ebpf.runtime.NvmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ObjDefinitions.*;
import static me.bechberger.ebpf.runtime.OctepDefinitions.*;
import static me.bechberger.ebpf.runtime.OdDefinitions.*;
import static me.bechberger.ebpf.runtime.OfDefinitions.*;
import static me.bechberger.ebpf.runtime.OhciDefinitions.*;
import static me.bechberger.ebpf.runtime.OldDefinitions.*;
import static me.bechberger.ebpf.runtime.OomDefinitions.*;
import static me.bechberger.ebpf.runtime.OpalDefinitions.*;
import static me.bechberger.ebpf.runtime.OpenDefinitions.*;
import static me.bechberger.ebpf.runtime.OppDefinitions.*;
import static me.bechberger.ebpf.runtime.OsnoiseDefinitions.*;
import static me.bechberger.ebpf.runtime.P4Definitions.*;
import static me.bechberger.ebpf.runtime.PacketDefinitions.*;
import static me.bechberger.ebpf.runtime.PadataDefinitions.*;
import static me.bechberger.ebpf.runtime.PageDefinitions.*;
import static me.bechberger.ebpf.runtime.PagemapDefinitions.*;
import static me.bechberger.ebpf.runtime.PagesDefinitions.*;
import static me.bechberger.ebpf.runtime.PalmasDefinitions.*;
import static me.bechberger.ebpf.runtime.PanelDefinitions.*;
import static me.bechberger.ebpf.runtime.ParamDefinitions.*;
import static me.bechberger.ebpf.runtime.ParseDefinitions.*;
import static me.bechberger.ebpf.runtime.PartDefinitions.*;
import static me.bechberger.ebpf.runtime.PathDefinitions.*;
import static me.bechberger.ebpf.runtime.PcapDefinitions.*;
import static me.bechberger.ebpf.runtime.PccDefinitions.*;
import static me.bechberger.ebpf.runtime.PciDefinitions.*;
import static me.bechberger.ebpf.runtime.PcibiosDefinitions.*;
import static me.bechberger.ebpf.runtime.PcieDefinitions.*;
import static me.bechberger.ebpf.runtime.PciehpDefinitions.*;
import static me.bechberger.ebpf.runtime.PcimDefinitions.*;
import static me.bechberger.ebpf.runtime.PcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PercpuDefinitions.*;
import static me.bechberger.ebpf.runtime.PerfDefinitions.*;
import static me.bechberger.ebpf.runtime.PfifoDefinitions.*;
import static me.bechberger.ebpf.runtime.PfnDefinitions.*;
import static me.bechberger.ebpf.runtime.PhyDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysDefinitions.*;
import static me.bechberger.ebpf.runtime.PhysdevDefinitions.*;
import static me.bechberger.ebpf.runtime.PickDefinitions.*;
import static me.bechberger.ebpf.runtime.PidDefinitions.*;
import static me.bechberger.ebpf.runtime.PidfsDefinitions.*;
import static me.bechberger.ebpf.runtime.PidsDefinitions.*;
import static me.bechberger.ebpf.runtime.PiixDefinitions.*;
import static me.bechberger.ebpf.runtime.PinDefinitions.*;
import static me.bechberger.ebpf.runtime.PinconfDefinitions.*;
import static me.bechberger.ebpf.runtime.PinctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.PingDefinitions.*;
import static me.bechberger.ebpf.runtime.PinmuxDefinitions.*;
import static me.bechberger.ebpf.runtime.PipeDefinitions.*;
import static me.bechberger.ebpf.runtime.PirqDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs1padDefinitions.*;
import static me.bechberger.ebpf.runtime.Pkcs7Definitions.*;
import static me.bechberger.ebpf.runtime.PlatformDefinitions.*;
import static me.bechberger.ebpf.runtime.PldmfwDefinitions.*;
import static me.bechberger.ebpf.runtime.Pm860xDefinitions.*;
import static me.bechberger.ebpf.runtime.PmDefinitions.*;
import static me.bechberger.ebpf.runtime.PmcDefinitions.*;
import static me.bechberger.ebpf.runtime.PmdDefinitions.*;
import static me.bechberger.ebpf.runtime.PmuDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpDefinitions.*;
import static me.bechberger.ebpf.runtime.PnpacpiDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicyDefinitions.*;
import static me.bechberger.ebpf.runtime.PolicydbDefinitions.*;
import static me.bechberger.ebpf.runtime.PollDefinitions.*;
import static me.bechberger.ebpf.runtime.Poly1305Definitions.*;
import static me.bechberger.ebpf.runtime.PopulateDefinitions.*;
import static me.bechberger.ebpf.runtime.PortDefinitions.*;
import static me.bechberger.ebpf.runtime.PosixDefinitions.*;
import static me.bechberger.ebpf.runtime.PowerDefinitions.*;
import static me.bechberger.ebpf.runtime.PowercapDefinitions.*;
import static me.bechberger.ebpf.runtime.PppDefinitions.*;
import static me.bechberger.ebpf.runtime.PpsDefinitions.*;
import static me.bechberger.ebpf.runtime.PrDefinitions.*;
import static me.bechberger.ebpf.runtime.PrbDefinitions.*;
import static me.bechberger.ebpf.runtime.PreemptDefinitions.*;
import static me.bechberger.ebpf.runtime.PrepareDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintDefinitions.*;
import static me.bechberger.ebpf.runtime.PrintkDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbeDefinitions.*;
import static me.bechberger.ebpf.runtime.ProbestubDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcDefinitions.*;
import static me.bechberger.ebpf.runtime.ProcessDefinitions.*;
import static me.bechberger.ebpf.runtime.ProfileDefinitions.*;
import static me.bechberger.ebpf.runtime.ProgDefinitions.*;
import static me.bechberger.ebpf.runtime.PropagateDefinitions.*;
import static me.bechberger.ebpf.runtime.ProtoDefinitions.*;
import static me.bechberger.ebpf.runtime.Ps2Definitions.*;
import static me.bechberger.ebpf.runtime.PseDefinitions.*;
import static me.bechberger.ebpf.runtime.PseudoDefinitions.*;
import static me.bechberger.ebpf.runtime.PsiDefinitions.*;
import static me.bechberger.ebpf.runtime.PskbDefinitions.*;
import static me.bechberger.ebpf.runtime.PstoreDefinitions.*;
import static me.bechberger.ebpf.runtime.PtDefinitions.*;
import static me.bechberger.ebpf.runtime.PtdumpDefinitions.*;
import static me.bechberger.ebpf.runtime.PteDefinitions.*;
import static me.bechberger.ebpf.runtime.PtiDefinitions.*;
import static me.bechberger.ebpf.runtime.PtpDefinitions.*;
import static me.bechberger.ebpf.runtime.PtraceDefinitions.*;
import static me.bechberger.ebpf.runtime.PtyDefinitions.*;
import static me.bechberger.ebpf.runtime.PushDefinitions.*;
import static me.bechberger.ebpf.runtime.PutDefinitions.*;
import static me.bechberger.ebpf.runtime.PvDefinitions.*;
import static me.bechberger.ebpf.runtime.PvclockDefinitions.*;
import static me.bechberger.ebpf.runtime.PwmDefinitions.*;
import static me.bechberger.ebpf.runtime.QdiscDefinitions.*;
import static me.bechberger.ebpf.runtime.QhDefinitions.*;
import static me.bechberger.ebpf.runtime.QiDefinitions.*;
import static me.bechberger.ebpf.runtime.QueueDefinitions.*;
import static me.bechberger.ebpf.runtime.QuirkDefinitions.*;
import static me.bechberger.ebpf.runtime.QuotaDefinitions.*;
import static me.bechberger.ebpf.runtime.RadixDefinitions.*;
import static me.bechberger.ebpf.runtime.RamfsDefinitions.*;
import static me.bechberger.ebpf.runtime.RandomDefinitions.*;
import static me.bechberger.ebpf.runtime.RangeDefinitions.*;
import static me.bechberger.ebpf.runtime.Raw6Definitions.*;
import static me.bechberger.ebpf.runtime.RawDefinitions.*;
import static me.bechberger.ebpf.runtime.Rawv6Definitions.*;
import static me.bechberger.ebpf.runtime.RbDefinitions.*;
import static me.bechberger.ebpf.runtime.Rc5t583Definitions.*;
import static me.bechberger.ebpf.runtime.RcuDefinitions.*;
import static me.bechberger.ebpf.runtime.RdevDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmaDefinitions.*;
import static me.bechberger.ebpf.runtime.RdmacgDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtDefinitions.*;
import static me.bechberger.ebpf.runtime.RdtgroupDefinitions.*;
import static me.bechberger.ebpf.runtime.ReadDefinitions.*;
import static me.bechberger.ebpf.runtime.ReclaimDefinitions.*;
import static me.bechberger.ebpf.runtime.RegDefinitions.*;
import static me.bechberger.ebpf.runtime.RegcacheDefinitions.*;
import static me.bechberger.ebpf.runtime.RegisterDefinitions.*;
import static me.bechberger.ebpf.runtime.RegmapDefinitions.*;
import static me.bechberger.ebpf.runtime.RegulatorDefinitions.*;
import static me.bechberger.ebpf.runtime.RelayDefinitions.*;
import static me.bechberger.ebpf.runtime.ReleaseDefinitions.*;
import static me.bechberger.ebpf.runtime.RemapDefinitions.*;
import static me.bechberger.ebpf.runtime.RemoveDefinitions.*;
import static me.bechberger.ebpf.runtime.ReplaceDefinitions.*;
import static me.bechberger.ebpf.runtime.ReportDefinitions.*;
import static me.bechberger.ebpf.runtime.RequestDefinitions.*;
import static me.bechberger.ebpf.runtime.ResctrlDefinitions.*;
import static me.bechberger.ebpf.runtime.ReserveDefinitions.*;
import static me.bechberger.ebpf.runtime.ResetDefinitions.*;
import static me.bechberger.ebpf.runtime.ResourceDefinitions.*;
import static me.bechberger.ebpf.runtime.RestoreDefinitions.*;
import static me.bechberger.ebpf.runtime.RestrictDefinitions.*;
import static me.bechberger.ebpf.runtime.ResumeDefinitions.*;
import static me.bechberger.ebpf.runtime.RethookDefinitions.*;
import static me.bechberger.ebpf.runtime.ReuseportDefinitions.*;
import static me.bechberger.ebpf.runtime.RfkillDefinitions.*;
import static me.bechberger.ebpf.runtime.RhashtableDefinitions.*;
import static me.bechberger.ebpf.runtime.RingDefinitions.*;
import static me.bechberger.ebpf.runtime.RingbufDefinitions.*;
import static me.bechberger.ebpf.runtime.RioDefinitions.*;
import static me.bechberger.ebpf.runtime.RngDefinitions.*;
import static me.bechberger.ebpf.runtime.RoleDefinitions.*;
import static me.bechberger.ebpf.runtime.RpcDefinitions.*;
import static me.bechberger.ebpf.runtime.RpmDefinitions.*;
import static me.bechberger.ebpf.runtime.RprocDefinitions.*;
import static me.bechberger.ebpf.runtime.RqDefinitions.*;
import static me.bechberger.ebpf.runtime.RsaDefinitions.*;
import static me.bechberger.ebpf.runtime.RsassaDefinitions.*;
import static me.bechberger.ebpf.runtime.RseqDefinitions.*;
import static me.bechberger.ebpf.runtime.RssDefinitions.*;
import static me.bechberger.ebpf.runtime.Rt6Definitions.*;
import static me.bechberger.ebpf.runtime.RtDefinitions.*;
import static me.bechberger.ebpf.runtime.RtcDefinitions.*;
import static me.bechberger.ebpf.runtime.RtmDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnetlinkDefinitions.*;
import static me.bechberger.ebpf.runtime.RtnlDefinitions.*;
import static me.bechberger.ebpf.runtime.RunDefinitions.*;
import static me.bechberger.ebpf.runtime.RustDefinitions.*;
import static me.bechberger.ebpf.runtime.RvDefinitions.*;
import static me.bechberger.ebpf.runtime.RxDefinitions.*;
import static me.bechberger.ebpf.runtime.SDefinitions.*;
import static me.bechberger.ebpf.runtime.SataDefinitions.*;
import static me.bechberger.ebpf.runtime.SaveDefinitions.*;
import static me.bechberger.ebpf.runtime.SavedDefinitions.*;
import static me.bechberger.ebpf.runtime.SbitmapDefinitions.*;
import static me.bechberger.ebpf.runtime.ScanDefinitions.*;
import static me.bechberger.ebpf.runtime.SccnxpDefinitions.*;
import static me.bechberger.ebpf.runtime.SchedDefinitions.*;
import static me.bechberger.ebpf.runtime.ScheduleDefinitions.*;
import static me.bechberger.ebpf.runtime.ScmDefinitions.*;
import static me.bechberger.ebpf.runtime.ScsiDefinitions.*;
import static me.bechberger.ebpf.runtime.SctpDefinitions.*;
import static me.bechberger.ebpf.runtime.ScxDefinitions.*;
import static me.bechberger.ebpf.runtime.SdDefinitions.*;
import static me.bechberger.ebpf.runtime.SdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SdioDefinitions.*;
import static me.bechberger.ebpf.runtime.SeccompDefinitions.*;
import static me.bechberger.ebpf.runtime.SecurityDefinitions.*;
import static me.bechberger.ebpf.runtime.Seg6Definitions.*;
import static me.bechberger.ebpf.runtime.SelDefinitions.*;
import static me.bechberger.ebpf.runtime.SelectDefinitions.*;
import static me.bechberger.ebpf.runtime.SelinuxDefinitions.*;
import static me.bechberger.ebpf.runtime.SendDefinitions.*;
import static me.bechberger.ebpf.runtime.SeqDefinitions.*;
import static me.bechberger.ebpf.runtime.SerdevDefinitions.*;
import static me.bechberger.ebpf.runtime.Serial8250Definitions.*;
import static me.bechberger.ebpf.runtime.SerialDefinitions.*;
import static me.bechberger.ebpf.runtime.SerioDefinitions.*;
import static me.bechberger.ebpf.runtime.SetDefinitions.*;
import static me.bechberger.ebpf.runtime.SetupDefinitions.*;
import static me.bechberger.ebpf.runtime.SevDefinitions.*;
import static me.bechberger.ebpf.runtime.SfpDefinitions.*;
import static me.bechberger.ebpf.runtime.SgDefinitions.*;
import static me.bechberger.ebpf.runtime.SgxDefinitions.*;
import static me.bechberger.ebpf.runtime.Sha1Definitions.*;
import static me.bechberger.ebpf.runtime.Sha256Definitions.*;
import static me.bechberger.ebpf.runtime.Sha512Definitions.*;
import static me.bechberger.ebpf.runtime.ShashDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmDefinitions.*;
import static me.bechberger.ebpf.runtime.ShmemDefinitions.*;
import static me.bechberger.ebpf.runtime.ShouldDefinitions.*;
import static me.bechberger.ebpf.runtime.ShowDefinitions.*;
import static me.bechberger.ebpf.runtime.ShpchpDefinitions.*;
import static me.bechberger.ebpf.runtime.ShrinkDefinitions.*;
import static me.bechberger.ebpf.runtime.SidtabDefinitions.*;
import static me.bechberger.ebpf.runtime.SimpleDefinitions.*;
import static me.bechberger.ebpf.runtime.SingleDefinitions.*;
import static me.bechberger.ebpf.runtime.SisDefinitions.*;
import static me.bechberger.ebpf.runtime.SkDefinitions.*;
import static me.bechberger.ebpf.runtime.SkbDefinitions.*;
import static me.bechberger.ebpf.runtime.SkcipherDefinitions.*;
import static me.bechberger.ebpf.runtime.SkxDefinitions.*;
import static me.bechberger.ebpf.runtime.SlabDefinitions.*;
import static me.bechberger.ebpf.runtime.SmackDefinitions.*;
import static me.bechberger.ebpf.runtime.SmeDefinitions.*;
import static me.bechberger.ebpf.runtime.SmkDefinitions.*;
import static me.bechberger.ebpf.runtime.SmpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnapshotDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbDefinitions.*;
import static me.bechberger.ebpf.runtime.SnbepDefinitions.*;
import static me.bechberger.ebpf.runtime.SnpDefinitions.*;
import static me.bechberger.ebpf.runtime.SnrDefinitions.*;
import static me.bechberger.ebpf.runtime.SocDefinitions.*;
import static me.bechberger.ebpf.runtime.SockDefinitions.*;
import static me.bechberger.ebpf.runtime.SoftwareDefinitions.*;
import static me.bechberger.ebpf.runtime.SparseDefinitions.*;
import static me.bechberger.ebpf.runtime.SpiDefinitions.*;
import static me.bechberger.ebpf.runtime.SpliceDefinitions.*;
import static me.bechberger.ebpf.runtime.SplitDefinitions.*;
import static me.bechberger.ebpf.runtime.SprDefinitions.*;
import static me.bechberger.ebpf.runtime.SquashfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SrDefinitions.*;
import static me.bechberger.ebpf.runtime.SramDefinitions.*;
import static me.bechberger.ebpf.runtime.SrcuDefinitions.*;
import static me.bechberger.ebpf.runtime.SriovDefinitions.*;
import static me.bechberger.ebpf.runtime.StackDefinitions.*;
import static me.bechberger.ebpf.runtime.StartDefinitions.*;
import static me.bechberger.ebpf.runtime.StatDefinitions.*;
import static me.bechberger.ebpf.runtime.StaticDefinitions.*;
import static me.bechberger.ebpf.runtime.StatsDefinitions.*;
import static me.bechberger.ebpf.runtime.StopDefinitions.*;
import static me.bechberger.ebpf.runtime.StoreDefinitions.*;
import static me.bechberger.ebpf.runtime.StripeDefinitions.*;
import static me.bechberger.ebpf.runtime.StrpDefinitions.*;
import static me.bechberger.ebpf.runtime.SubflowDefinitions.*;
import static me.bechberger.ebpf.runtime.SubmitDefinitions.*;
import static me.bechberger.ebpf.runtime.SugovDefinitions.*;
import static me.bechberger.ebpf.runtime.SuperDefinitions.*;
import static me.bechberger.ebpf.runtime.SuspendDefinitions.*;
import static me.bechberger.ebpf.runtime.SvcDefinitions.*;
import static me.bechberger.ebpf.runtime.SvsmDefinitions.*;
import static me.bechberger.ebpf.runtime.SwDefinitions.*;
import static me.bechberger.ebpf.runtime.SwapDefinitions.*;
import static me.bechberger.ebpf.runtime.SwiotlbDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchDefinitions.*;
import static me.bechberger.ebpf.runtime.SwitchdevDefinitions.*;
import static me.bechberger.ebpf.runtime.SwsuspDefinitions.*;
import static me.bechberger.ebpf.runtime.Sx150xDefinitions.*;
import static me.bechberger.ebpf.runtime.SyncDefinitions.*;
import static me.bechberger.ebpf.runtime.SynchronizeDefinitions.*;
import static me.bechberger.ebpf.runtime.SynthDefinitions.*;
import static me.bechberger.ebpf.runtime.SysDefinitions.*;
import static me.bechberger.ebpf.runtime.SyscallDefinitions.*;
import static me.bechberger.ebpf.runtime.SysctlDefinitions.*;
import static me.bechberger.ebpf.runtime.SysfsDefinitions.*;
import static me.bechberger.ebpf.runtime.SysrqDefinitions.*;
import static me.bechberger.ebpf.runtime.SystemDefinitions.*;
import static me.bechberger.ebpf.runtime.SysvecDefinitions.*;
import static me.bechberger.ebpf.runtime.TargetDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskDefinitions.*;
import static me.bechberger.ebpf.runtime.TaskletDefinitions.*;
import static me.bechberger.ebpf.runtime.TbootDefinitions.*;
import static me.bechberger.ebpf.runtime.TcDefinitions.*;
import static me.bechberger.ebpf.runtime.TcfDefinitions.*;
import static me.bechberger.ebpf.runtime.TcpDefinitions.*;
import static me.bechberger.ebpf.runtime.TcxDefinitions.*;
import static me.bechberger.ebpf.runtime.TdhDefinitions.*;
import static me.bechberger.ebpf.runtime.TdxDefinitions.*;
import static me.bechberger.ebpf.runtime.TestDefinitions.*;
import static me.bechberger.ebpf.runtime.TextDefinitions.*;
import static me.bechberger.ebpf.runtime.TgDefinitions.*;
import static me.bechberger.ebpf.runtime.ThermalDefinitions.*;
import static me.bechberger.ebpf.runtime.ThreadDefinitions.*;
import static me.bechberger.ebpf.runtime.ThrotlDefinitions.*;
import static me.bechberger.ebpf.runtime.TickDefinitions.*;
import static me.bechberger.ebpf.runtime.TimekeepingDefinitions.*;
import static me.bechberger.ebpf.runtime.TimensDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerfdDefinitions.*;
import static me.bechberger.ebpf.runtime.TimerlatDefinitions.*;
import static me.bechberger.ebpf.runtime.TkDefinitions.*;
import static me.bechberger.ebpf.runtime.TlbDefinitions.*;
import static me.bechberger.ebpf.runtime.TlsDefinitions.*;
import static me.bechberger.ebpf.runtime.TmigrDefinitions.*;
import static me.bechberger.ebpf.runtime.TnumDefinitions.*;
import static me.bechberger.ebpf.runtime.ToDefinitions.*;
import static me.bechberger.ebpf.runtime.TomoyoDefinitions.*;
import static me.bechberger.ebpf.runtime.TopologyDefinitions.*;
import static me.bechberger.ebpf.runtime.TouchDefinitions.*;
import static me.bechberger.ebpf.runtime.TpacketDefinitions.*;
import static me.bechberger.ebpf.runtime.Tpm1Definitions.*;
import static me.bechberger.ebpf.runtime.Tpm2Definitions.*;
import static me.bechberger.ebpf.runtime.TpmDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps6586xDefinitions.*;
import static me.bechberger.ebpf.runtime.Tps65910Definitions.*;
import static me.bechberger.ebpf.runtime.TraceDefinitions.*;
import static me.bechberger.ebpf.runtime.TracefsDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceiterDefinitions.*;
import static me.bechberger.ebpf.runtime.TracepointDefinitions.*;
import static me.bechberger.ebpf.runtime.TraceprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.TracerDefinitions.*;
import static me.bechberger.ebpf.runtime.TracingDefinitions.*;
import static me.bechberger.ebpf.runtime.TransportDefinitions.*;
import static me.bechberger.ebpf.runtime.TrieDefinitions.*;
import static me.bechberger.ebpf.runtime.TruncateDefinitions.*;
import static me.bechberger.ebpf.runtime.TrustedDefinitions.*;
import static me.bechberger.ebpf.runtime.TryDefinitions.*;
import static me.bechberger.ebpf.runtime.TscDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyDefinitions.*;
import static me.bechberger.ebpf.runtime.TtyportDefinitions.*;
import static me.bechberger.ebpf.runtime.TunDefinitions.*;
import static me.bechberger.ebpf.runtime.Twl4030Definitions.*;
import static me.bechberger.ebpf.runtime.Twl6040Definitions.*;
import static me.bechberger.ebpf.runtime.TwlDefinitions.*;
import static me.bechberger.ebpf.runtime.TxDefinitions.*;
import static me.bechberger.ebpf.runtime.TypeDefinitions.*;
import static me.bechberger.ebpf.runtime.UDefinitions.*;
import static me.bechberger.ebpf.runtime.UartDefinitions.*;
import static me.bechberger.ebpf.runtime.UbsanDefinitions.*;
import static me.bechberger.ebpf.runtime.Udp4Definitions.*;
import static me.bechberger.ebpf.runtime.Udp6Definitions.*;
import static me.bechberger.ebpf.runtime.UdpDefinitions.*;
import static me.bechberger.ebpf.runtime.Udpv6Definitions.*;
import static me.bechberger.ebpf.runtime.UhciDefinitions.*;
import static me.bechberger.ebpf.runtime.UinputDefinitions.*;
import static me.bechberger.ebpf.runtime.UncoreDefinitions.*;
import static me.bechberger.ebpf.runtime.Univ8250Definitions.*;
import static me.bechberger.ebpf.runtime.UnixDefinitions.*;
import static me.bechberger.ebpf.runtime.UnlockDefinitions.*;
import static me.bechberger.ebpf.runtime.UnmapDefinitions.*;
import static me.bechberger.ebpf.runtime.UnregisterDefinitions.*;
import static me.bechberger.ebpf.runtime.UpdateDefinitions.*;
import static me.bechberger.ebpf.runtime.UprobeDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbDefinitions.*;
import static me.bechberger.ebpf.runtime.UsbdevfsDefinitions.*;
import static me.bechberger.ebpf.runtime.UserDefinitions.*;
import static me.bechberger.ebpf.runtime.UserfaultfdDefinitions.*;
import static me.bechberger.ebpf.runtime.Utf8Definitions.*;
import static me.bechberger.ebpf.runtime.UvDefinitions.*;
import static me.bechberger.ebpf.runtime.UvhDefinitions.*;
import static me.bechberger.ebpf.runtime.ValidateDefinitions.*;
import static me.bechberger.ebpf.runtime.VcDefinitions.*;
import static me.bechberger.ebpf.runtime.VcapDefinitions.*;
import static me.bechberger.ebpf.runtime.VcpuDefinitions.*;
import static me.bechberger.ebpf.runtime.VcsDefinitions.*;
import static me.bechberger.ebpf.runtime.VdsoDefinitions.*;
import static me.bechberger.ebpf.runtime.VerifyDefinitions.*;
import static me.bechberger.ebpf.runtime.VfatDefinitions.*;
import static me.bechberger.ebpf.runtime.VfsDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaDefinitions.*;
import static me.bechberger.ebpf.runtime.VgaconDefinitions.*;
import static me.bechberger.ebpf.runtime.ViaDefinitions.*;
import static me.bechberger.ebpf.runtime.ViommuDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtblkDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtioDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtnetDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.VirtscsiDefinitions.*;
import static me.bechberger.ebpf.runtime.VlanDefinitions.*;
import static me.bechberger.ebpf.runtime.VliDefinitions.*;
import static me.bechberger.ebpf.runtime.VmDefinitions.*;
import static me.bechberger.ebpf.runtime.VmaDefinitions.*;
import static me.bechberger.ebpf.runtime.VmallocDefinitions.*;
import static me.bechberger.ebpf.runtime.VmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmeDefinitions.*;
import static me.bechberger.ebpf.runtime.VmemmapDefinitions.*;
import static me.bechberger.ebpf.runtime.VmpressureDefinitions.*;
import static me.bechberger.ebpf.runtime.VmstatDefinitions.*;
import static me.bechberger.ebpf.runtime.VmwareDefinitions.*;
import static me.bechberger.ebpf.runtime.VpDefinitions.*;
import static me.bechberger.ebpf.runtime.VringDefinitions.*;
import static me.bechberger.ebpf.runtime.VtDefinitions.*;
import static me.bechberger.ebpf.runtime.WaitDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeDefinitions.*;
import static me.bechberger.ebpf.runtime.WakeupDefinitions.*;
import static me.bechberger.ebpf.runtime.WalkDefinitions.*;
import static me.bechberger.ebpf.runtime.WarnDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchDefinitions.*;
import static me.bechberger.ebpf.runtime.WatchdogDefinitions.*;
import static me.bechberger.ebpf.runtime.WbDefinitions.*;
import static me.bechberger.ebpf.runtime.WbtDefinitions.*;
import static me.bechberger.ebpf.runtime.WiphyDefinitions.*;
import static me.bechberger.ebpf.runtime.WirelessDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm831xDefinitions.*;
import static me.bechberger.ebpf.runtime.Wm8350Definitions.*;
import static me.bechberger.ebpf.runtime.WorkqueueDefinitions.*;
import static me.bechberger.ebpf.runtime.WpDefinitions.*;
import static me.bechberger.ebpf.runtime.WqDefinitions.*;
import static me.bechberger.ebpf.runtime.WriteDefinitions.*;
import static me.bechberger.ebpf.runtime.WritebackDefinitions.*;
import static me.bechberger.ebpf.runtime.WwDefinitions.*;
import static me.bechberger.ebpf.runtime.X2apicDefinitions.*;
import static me.bechberger.ebpf.runtime.X509Definitions.*;
import static me.bechberger.ebpf.runtime.X64Definitions.*;
import static me.bechberger.ebpf.runtime.X86Definitions.*;
import static me.bechberger.ebpf.runtime.XaDefinitions.*;
import static me.bechberger.ebpf.runtime.XasDefinitions.*;
import static me.bechberger.ebpf.runtime.XattrDefinitions.*;
import static me.bechberger.ebpf.runtime.XbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdbcDefinitions.*;
import static me.bechberger.ebpf.runtime.XdpDefinitions.*;
import static me.bechberger.ebpf.runtime.XenDefinitions.*;
import static me.bechberger.ebpf.runtime.XenbusDefinitions.*;
import static me.bechberger.ebpf.runtime.XennetDefinitions.*;
import static me.bechberger.ebpf.runtime.XenpfDefinitions.*;
import static me.bechberger.ebpf.runtime.Xfrm4Definitions.*;
import static me.bechberger.ebpf.runtime.Xfrm6Definitions.*;
import static me.bechberger.ebpf.runtime.XfrmDefinitions.*;
import static me.bechberger.ebpf.runtime.XhciDefinitions.*;
import static me.bechberger.ebpf.runtime.XpDefinitions.*;
import static me.bechberger.ebpf.runtime.XsDefinitions.*;
import static me.bechberger.ebpf.runtime.XskDefinitions.*;
import static me.bechberger.ebpf.runtime.XtsDefinitions.*;
import static me.bechberger.ebpf.runtime.XzDefinitions.*;
import static me.bechberger.ebpf.runtime.ZapDefinitions.*;
import static me.bechberger.ebpf.runtime.ZlibDefinitions.*;
import static me.bechberger.ebpf.runtime.ZoneDefinitions.*;
import static me.bechberger.ebpf.runtime.ZpoolDefinitions.*;
import static me.bechberger.ebpf.runtime.ZsDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with zstd
 */
@java.lang.SuppressWarnings("unused")
public final class ZstdDefinitions {
  public static final @Unsigned int ZSTD_error_no_error = 0;

  public static final @Unsigned int ZSTD_error_GENERIC = 1;

  public static final @Unsigned int ZSTD_error_prefix_unknown = 10;

  public static final @Unsigned int ZSTD_error_version_unsupported = 12;

  public static final @Unsigned int ZSTD_error_frameParameter_unsupported = 14;

  public static final @Unsigned int ZSTD_error_frameParameter_windowTooLarge = 16;

  public static final @Unsigned int ZSTD_error_corruption_detected = 20;

  public static final @Unsigned int ZSTD_error_checksum_wrong = 22;

  public static final @Unsigned int ZSTD_error_literals_headerWrong = 24;

  public static final @Unsigned int ZSTD_error_dictionary_corrupted = 30;

  public static final @Unsigned int ZSTD_error_dictionary_wrong = 32;

  public static final @Unsigned int ZSTD_error_dictionaryCreation_failed = 34;

  public static final @Unsigned int ZSTD_error_parameter_unsupported = 40;

  public static final @Unsigned int ZSTD_error_parameter_combination_unsupported = 41;

  public static final @Unsigned int ZSTD_error_parameter_outOfBound = 42;

  public static final @Unsigned int ZSTD_error_tableLog_tooLarge = 44;

  public static final @Unsigned int ZSTD_error_maxSymbolValue_tooLarge = 46;

  public static final @Unsigned int ZSTD_error_maxSymbolValue_tooSmall = 48;

  public static final @Unsigned int ZSTD_error_cannotProduce_uncompressedBlock = 49;

  public static final @Unsigned int ZSTD_error_stabilityCondition_notRespected = 50;

  public static final @Unsigned int ZSTD_error_stage_wrong = 60;

  public static final @Unsigned int ZSTD_error_init_missing = 62;

  public static final @Unsigned int ZSTD_error_memory_allocation = 64;

  public static final @Unsigned int ZSTD_error_workSpace_tooSmall = 66;

  public static final @Unsigned int ZSTD_error_dstSize_tooSmall = 70;

  public static final @Unsigned int ZSTD_error_srcSize_wrong = 72;

  public static final @Unsigned int ZSTD_error_dstBuffer_null = 74;

  public static final @Unsigned int ZSTD_error_noForwardProgress_destFull = 80;

  public static final @Unsigned int ZSTD_error_noForwardProgress_inputEmpty = 82;

  public static final @Unsigned int ZSTD_error_frameIndex_tooLarge = 100;

  public static final @Unsigned int ZSTD_error_seekableIO = 102;

  public static final @Unsigned int ZSTD_error_dstBuffer_wrong = 104;

  public static final @Unsigned int ZSTD_error_srcBuffer_wrong = 105;

  public static final @Unsigned int ZSTD_error_sequenceProducer_failed = 106;

  public static final @Unsigned int ZSTD_error_externalSequences_invalid = 107;

  public static final @Unsigned int ZSTD_error_maxCode = 120;

  public static final @Unsigned int ZSTD_c_compressionLevel = 100;

  public static final @Unsigned int ZSTD_c_windowLog = 101;

  public static final @Unsigned int ZSTD_c_hashLog = 102;

  public static final @Unsigned int ZSTD_c_chainLog = 103;

  public static final @Unsigned int ZSTD_c_searchLog = 104;

  public static final @Unsigned int ZSTD_c_minMatch = 105;

  public static final @Unsigned int ZSTD_c_targetLength = 106;

  public static final @Unsigned int ZSTD_c_strategy = 107;

  public static final @Unsigned int ZSTD_c_targetCBlockSize = 130;

  public static final @Unsigned int ZSTD_c_enableLongDistanceMatching = 160;

  public static final @Unsigned int ZSTD_c_ldmHashLog = 161;

  public static final @Unsigned int ZSTD_c_ldmMinMatch = 162;

  public static final @Unsigned int ZSTD_c_ldmBucketSizeLog = 163;

  public static final @Unsigned int ZSTD_c_ldmHashRateLog = 164;

  public static final @Unsigned int ZSTD_c_contentSizeFlag = 200;

  public static final @Unsigned int ZSTD_c_checksumFlag = 201;

  public static final @Unsigned int ZSTD_c_dictIDFlag = 202;

  public static final @Unsigned int ZSTD_c_nbWorkers = 400;

  public static final @Unsigned int ZSTD_c_jobSize = 401;

  public static final @Unsigned int ZSTD_c_overlapLog = 402;

  public static final @Unsigned int ZSTD_c_experimentalParam1 = 500;

  public static final @Unsigned int ZSTD_c_experimentalParam2 = 10;

  public static final @Unsigned int ZSTD_c_experimentalParam3 = 1000;

  public static final @Unsigned int ZSTD_c_experimentalParam4 = 1001;

  public static final @Unsigned int ZSTD_c_experimentalParam5 = 1002;

  public static final @Unsigned int ZSTD_c_experimentalParam7 = 1004;

  public static final @Unsigned int ZSTD_c_experimentalParam8 = 1005;

  public static final @Unsigned int ZSTD_c_experimentalParam9 = 1006;

  public static final @Unsigned int ZSTD_c_experimentalParam10 = 1007;

  public static final @Unsigned int ZSTD_c_experimentalParam11 = 1008;

  public static final @Unsigned int ZSTD_c_experimentalParam12 = 1009;

  public static final @Unsigned int ZSTD_c_experimentalParam13 = 1010;

  public static final @Unsigned int ZSTD_c_experimentalParam14 = 1011;

  public static final @Unsigned int ZSTD_c_experimentalParam15 = 1012;

  public static final @Unsigned int ZSTD_c_experimentalParam16 = 1013;

  public static final @Unsigned int ZSTD_c_experimentalParam17 = 1014;

  public static final @Unsigned int ZSTD_c_experimentalParam18 = 1015;

  public static final @Unsigned int ZSTD_c_experimentalParam19 = 1016;

  public static final @Unsigned int ZSTD_c_experimentalParam20 = 1017;

  public static final @Unsigned int ZSTD_reset_session_only = 1;

  public static final @Unsigned int ZSTD_reset_parameters = 2;

  public static final @Unsigned int ZSTD_reset_session_and_parameters = 3;

  public static final @Unsigned int ZSTD_dlm_byCopy = 0;

  public static final @Unsigned int ZSTD_dlm_byRef = 1;

  public static final @Unsigned int ZSTD_e_continue = 0;

  public static final @Unsigned int ZSTD_e_flush = 1;

  public static final @Unsigned int ZSTD_e_end = 2;

  public static final @Unsigned int ZSTD_dtlm_fast = 0;

  public static final @Unsigned int ZSTD_dtlm_full = 1;

  public static final @Unsigned int ZSTD_tfp_forCCtx = 0;

  public static final @Unsigned int ZSTD_tfp_forCDict = 1;

  public static final @Unsigned int ZSTD_cpm_noAttachDict = 0;

  public static final @Unsigned int ZSTD_cpm_attachDict = 1;

  public static final @Unsigned int ZSTD_cpm_createCDict = 2;

  public static final @Unsigned int ZSTD_cpm_unknown = 3;

  public static final @Unsigned int ZSTD_defaultDisallowed = 0;

  public static final @Unsigned int ZSTD_defaultAllowed = 1;

  public static final @Unsigned int ZSTD_resetTarget_CDict = 0;

  public static final @Unsigned int ZSTD_resetTarget_CCtx = 1;

  public static final @Unsigned int ZSTD_d_windowLogMax = 100;

  public static final @Unsigned int ZSTD_d_experimentalParam1 = 1000;

  public static final @Unsigned int ZSTD_d_experimentalParam2 = 1001;

  public static final @Unsigned int ZSTD_d_experimentalParam3 = 1002;

  public static final @Unsigned int ZSTD_d_experimentalParam4 = 1003;

  public static final @Unsigned int ZSTD_d_experimentalParam5 = 1004;

  public static final @Unsigned int ZSTD_d_experimentalParam6 = 1005;

  public static final @Unsigned int ZSTD_lo_isRegularOffset = 0;

  public static final @Unsigned int ZSTD_lo_isLongOffset = 1;

  @NotUsableInJava
  @BuiltinBPFFunction
  public static ZSTD_compressionParameters ZSTD_adjustCParams(ZSTD_compressionParameters cPar,
      @Unsigned long srcSize, @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static ZSTD_compressionParameters ZSTD_adjustCParams_internal(
      ZSTD_compressionParameters cPar, @Unsigned long srcSize, @Unsigned long dictSize,
      @OriginalName("ZSTD_CParamMode_e") ZSTD_cpm mode,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s useRowMatchFinder) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_allocateLiteralsBuffer($arg1, (const void*)$arg2, (const long unsigned int)$arg3, (const long unsigned int)$arg4, (const streaming_operation)$arg5, (const long unsigned int)$arg6, (const unsigned int)$arg7)")
  public static void ZSTD_allocateLiteralsBuffer(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, @Unsigned long litSize, streaming_operation streaming,
      @Unsigned long expectedWriteSize, @Unsigned int splitImmediately) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_dictMatchState_3($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_dictMatchState_3(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_dictMatchState_4($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_dictMatchState_4(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_dictMatchState_5($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_dictMatchState_5(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_dictMatchState_6($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_dictMatchState_6(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_extDict_3($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_extDict_3(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_extDict_4($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_extDict_4(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_extDict_5($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_extDict_5(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_extDict_6($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_extDict_6(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_noDict_3($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_noDict_3(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_noDict_4($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_noDict_4(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_noDict_5($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_noDict_5(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_btGetAllMatches_noDict_6($arg1, $arg2, $arg3, (const u8*)$arg4, (const const u8*)$arg5, (const unsigned int*)$arg6, (const unsigned int)$arg7, (const unsigned int)$arg8)")
  public static @Unsigned int ZSTD_btGetAllMatches_noDict_6(Ptr<ZSTD_match_t> matches,
      Ptr<ZSTD_MatchState_t> ms, Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iHighLimit,
      Ptr<java.lang. @Unsigned Integer> rep, @Unsigned int ll0, @Unsigned int lengthToBeat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_buildBlockEntropyStats((const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg1, (const struct {\n"
          + "  struct {\n"
          + "    long unsigned int CTable[257];\n"
          + "    repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "  } huf;\n"
          + "  struct {\n"
          + "    unsigned int offcodeCTable[193];\n"
          + "    unsigned int matchlengthCTable[363];\n"
          + "    unsigned int litlengthCTable[329];\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;\n"
          + "  } fse;\n"
          + "}*)$arg2, $arg3, (const ZSTD_CCtx_params_s*)$arg4, $arg5, $arg6, $arg7)")
  public static @Unsigned long ZSTD_buildBlockEntropyStats(Ptr<SeqStore_t> seqStorePtr,
      Ptr<ZSTD_entropyCTables_t> prevEntropy, Ptr<ZSTD_entropyCTables_t> nextEntropy,
      Ptr<ZSTD_CCtx_params_s> cctxParams, Ptr<ZSTD_entropyCTablesMetadata_t> entropyMetadata,
      Ptr<?> workspace, @Unsigned long wkspSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_buildBlockEntropyStats_literals((const void*)$arg1, $arg2, (const struct {\n"
          + "  long unsigned int CTable[257];\n"
          + "  repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "}*)$arg3, $arg4, $arg5, (const int)$arg6, $arg7, $arg8, $arg9)")
  public static @Unsigned long ZSTD_buildBlockEntropyStats_literals(Ptr<?> src,
      @Unsigned long srcSize, Ptr<ZSTD_hufCTables_t> prevHuf, Ptr<ZSTD_hufCTables_t> nextHuf,
      Ptr<ZSTD_hufCTablesMetadata_t> hufMetadata, int literalsCompressionIsDisabled,
      Ptr<?> workspace, @Unsigned long wkspSize, int hufFlags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_buildCTable($arg1, $arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const u8*)$arg8, $arg9, (const short int*)$arg10, $arg11, $arg12, (const unsigned int*)$arg13, $arg14, $arg15, $arg16)")
  public static @Unsigned long ZSTD_buildCTable(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> nextCTable,
      @Unsigned int FSELog,
      @OriginalName("SymbolEncodingType_e") hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t type,
      Ptr<java.lang. @Unsigned Integer> count, @Unsigned int max,
      Ptr<java.lang. @OriginalName("BYTE") Character> codeTable, @Unsigned long nbSeq,
      Ptr<java.lang.Short> defaultNorm, @Unsigned int defaultNormLog, @Unsigned int defaultMax,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> prevCTable,
      @Unsigned long prevCTableSize, Ptr<?> entropyWorkspace, @Unsigned long entropyWorkspaceSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_buildEntropyStatisticsAndEstimateSubBlockSize(
      Ptr<SeqStore_t> seqStore, Ptr<ZSTD_CCtx_s> zc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_buildFSETable($arg1, (const short int*)$arg2, $arg3, (const unsigned int*)$arg4, (const u8*)$arg5, $arg6, $arg7, $arg8, $arg9)")
  public static void ZSTD_buildFSETable(Ptr<ZSTD_seqSymbol> dt,
      Ptr<java.lang.Short> normalizedCounter, @Unsigned int maxSymbolValue,
      Ptr<java.lang. @Unsigned Integer> baseValue, Ptr<java.lang.Character> nbAdditionalBits,
      @Unsigned int tableLog, Ptr<?> wksp, @Unsigned long wkspSize, int bmi2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_buildFSETable_body_bmi2($arg1, (const short int*)$arg2, $arg3, (const unsigned int*)$arg4, (const u8*)$arg5, $arg6, $arg7, $arg8)")
  public static void ZSTD_buildFSETable_body_bmi2(Ptr<ZSTD_seqSymbol> dt,
      Ptr<java.lang.Short> normalizedCounter, @Unsigned int maxSymbolValue,
      Ptr<java.lang. @Unsigned Integer> baseValue, Ptr<java.lang.Character> nbAdditionalBits,
      @Unsigned int tableLog, Ptr<?> wksp, @Unsigned long wkspSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_buildFSETable_body_default($arg1, (const short int*)$arg2, $arg3, (const unsigned int*)$arg4, (const u8*)$arg5, $arg6, $arg7, $arg8)")
  public static void ZSTD_buildFSETable_body_default(Ptr<ZSTD_seqSymbol> dt,
      Ptr<java.lang.Short> normalizedCounter, @Unsigned int maxSymbolValue,
      Ptr<java.lang. @Unsigned Integer> baseValue, Ptr<java.lang.Character> nbAdditionalBits,
      @Unsigned int tableLog, Ptr<?> wksp, @Unsigned long wkspSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_buildSeqStore($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned long ZSTD_buildSeqStore(Ptr<ZSTD_CCtx_s> zc, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static ZSTD_bounds ZSTD_cParam_getBounds(@OriginalName("ZSTD_cParameter") ZSTD_c param) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_checkCParams(ZSTD_compressionParameters cParams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_checkContinuity($arg1, (const void*)$arg2, $arg3)")
  public static void ZSTD_checkContinuity(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_clearAllDicts(Ptr<ZSTD_CCtx_s> cctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_compress(Ptr<?> dst, @Unsigned long dstCapacity, Ptr<?> src,
      @Unsigned long srcSize, int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compress2(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_compressBegin(Ptr<ZSTD_CCtx_s> cctx, int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_advanced($arg1, (const void*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBegin_advanced(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dict,
      @Unsigned long dictSize, ZSTD_parameters params, @Unsigned long pledgedSrcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_advanced_internal($arg1, (const void*)$arg2, $arg3, $arg4, $arg5, (const ZSTD_CDict_s*)$arg6, (const ZSTD_CCtx_params_s*)$arg7, $arg8)")
  public static @Unsigned long ZSTD_compressBegin_advanced_internal(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<?> dict, @Unsigned long dictSize,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm, Ptr<ZSTD_CDict_s> cdict,
      Ptr<ZSTD_CCtx_params_s> params, @Unsigned long pledgedSrcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_internal($arg1, (const void*)$arg2, $arg3, $arg4, $arg5, (const ZSTD_CDict_s*)$arg6, (const ZSTD_CCtx_params_s*)$arg7, $arg8, $arg9)")
  public static @Unsigned long ZSTD_compressBegin_internal(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dict,
      @Unsigned long dictSize,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm, Ptr<ZSTD_CDict_s> cdict,
      Ptr<ZSTD_CCtx_params_s> params, @Unsigned long pledgedSrcSize,
      @OriginalName("ZSTD_buffered_policy_e") bufferedPolicy_of_ZSTD_CCtx_and_bufferedPolicy_of_ZSTD_CCtx_s zbuff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_usingCDict($arg1, (const ZSTD_CDict_s*)$arg2)")
  public static @Unsigned long ZSTD_compressBegin_usingCDict(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_usingCDict_advanced((const ZSTD_CCtx_s*)$arg1, (const const ZSTD_CDict_s*)$arg2, (const struct {\n"
          + "  int contentSizeFlag;\n"
          + "  int checksumFlag;\n"
          + "  int noDictIDFlag;\n"
          + "})$arg3, (const long long unsigned int)$arg4)")
  public static @Unsigned long ZSTD_compressBegin_usingCDict_advanced(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_CDict_s> cdict, ZSTD_frameParameters fParams, @Unsigned long pledgedSrcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_usingCDict_deprecated($arg1, (const ZSTD_CDict_s*)$arg2)")
  public static @Unsigned long ZSTD_compressBegin_usingCDict_deprecated(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_usingCDict_internal((const ZSTD_CCtx_s*)$arg1, (const const ZSTD_CDict_s*)$arg2, (const struct {\n"
          + "  int contentSizeFlag;\n"
          + "  int checksumFlag;\n"
          + "  int noDictIDFlag;\n"
          + "})$arg3, (const long long unsigned int)$arg4)")
  public static @Unsigned long ZSTD_compressBegin_usingCDict_internal(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_CDict_s> cdict, ZSTD_frameParameters fParams, @Unsigned long pledgedSrcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_usingDict($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static @Unsigned long ZSTD_compressBegin_usingDict(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dict,
      @Unsigned long dictSize, int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBegin_usingDict_deprecated($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static @Unsigned long ZSTD_compressBegin_usingDict_deprecated(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<?> dict, @Unsigned long dictSize, int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btlazy2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btlazy2(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btlazy2_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btlazy2_dictMatchState(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btlazy2_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btlazy2_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btopt($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btopt(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btopt_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btopt_dictMatchState(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btopt_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btopt_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btultra($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btultra(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btultra2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btultra2(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btultra_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btultra_dictMatchState(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_btultra_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_btultra_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_deprecated($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_deprecated(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_dictMatchState(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_dictMatchState_4($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_dictMatchState_4(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_dictMatchState_5($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_dictMatchState_5(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_dictMatchState_6($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_dictMatchState_6(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_dictMatchState_7($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_dictMatchState_7(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_extDict_generic($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const unsigned int)$arg6)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_extDict_generic(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize, @Unsigned int mls) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_noDict_4($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_noDict_4(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_noDict_5($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_noDict_5(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_noDict_6($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_noDict_6(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_doubleFast_noDict_7($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_doubleFast_noDict_7(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_dictMatchState(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_dictMatchState_4_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_dictMatchState_4_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_dictMatchState_5_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_dictMatchState_5_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_dictMatchState_6_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_dictMatchState_6_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_dictMatchState_7_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_dictMatchState_7_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_extDict_generic($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const unsigned int)$arg6, (const unsigned int)$arg7)")
  public static @Unsigned long ZSTD_compressBlock_fast_extDict_generic(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize, @Unsigned int mls, @Unsigned int hasStep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_4_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_4_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_4_1($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_4_1(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_5_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_5_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_5_1($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_5_1(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_6_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_6_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_6_1($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_6_1(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_7_0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_7_0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_fast_noDict_7_1($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_fast_noDict_7_1(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy_dedicatedDictSearch($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy_dedicatedDictSearch(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy_dedicatedDictSearch_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy_dedicatedDictSearch_row(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy_dictMatchState(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy_dictMatchState_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy_dictMatchState_row(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy_extDict_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy_extDict_row(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_greedy_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_greedy_row(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_internal($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6)")
  public static @Unsigned long ZSTD_compressBlock_internal(Ptr<ZSTD_CCtx_s> zc, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, @Unsigned int frame) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2_dedicatedDictSearch($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2_dedicatedDictSearch(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2_dedicatedDictSearch_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2_dedicatedDictSearch_row(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2_dictMatchState(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2_dictMatchState_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2_dictMatchState_row(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2_extDict_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2_extDict_row(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy2_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy2_row(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy_dedicatedDictSearch($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy_dedicatedDictSearch(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy_dedicatedDictSearch_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy_dedicatedDictSearch_row(
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy_dictMatchState($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy_dictMatchState(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy_dictMatchState_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy_dictMatchState_row(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy_extDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy_extDict(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy_extDict_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy_extDict_row(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_lazy_row($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressBlock_lazy_row(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_opt0($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const ZSTD)$arg6)")
  public static @Unsigned long ZSTD_compressBlock_opt0(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize, @OriginalName("ZSTD_dictMode_e") ZSTD dictMode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_opt2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const ZSTD)$arg6)")
  public static @Unsigned long ZSTD_compressBlock_opt2(Ptr<ZSTD_MatchState_t> ms,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep, Ptr<?> src,
      @Unsigned long srcSize, @OriginalName("ZSTD_dictMode_e") ZSTD dictMode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressBlock_splitBlock_internal($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, $arg7)")
  public static @Unsigned long ZSTD_compressBlock_splitBlock_internal(Ptr<ZSTD_CCtx_s> zc,
      Ptr<?> dst, @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long blockSize,
      @Unsigned int lastBlock, @Unsigned int nbSeq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_compressBound(@Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressCCtx($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6)")
  public static @Unsigned long ZSTD_compressCCtx(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressContinue($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressContinue(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressContinue_internal($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, $arg7)")
  public static @Unsigned long ZSTD_compressContinue_internal(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, @Unsigned int frame,
      @Unsigned int lastFrameChunk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressContinue_public($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressContinue_public(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressEnd($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressEnd(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressEnd_public($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_compressEnd_public(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressLiterals($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6, (const struct {\n"
          + "  long unsigned int CTable[257];\n"
          + "  repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "}*)$arg7, $arg8, $arg9, $arg10, $arg11, $arg12)")
  public static @Unsigned long ZSTD_compressLiterals(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<?> src, @Unsigned long srcSize, Ptr<?> entropyWorkspace,
      @Unsigned long entropyWorkspaceSize, Ptr<ZSTD_hufCTables_t> prevHuf,
      Ptr<ZSTD_hufCTables_t> nextHuf,
      @OriginalName("ZSTD_strategy") strategy_of_ZSTD_compressionParameters strategy,
      int disableLiteralCompression, int suspectUncompressible, int bmi2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressRleLiteralsBlock($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static @Unsigned long ZSTD_compressRleLiteralsBlock(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSeqStore_singleBlock($arg1, (const const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg2, (const repcodes_s*)$arg3, (const repcodes_s*)$arg4, $arg5, $arg6, (const void*)$arg7, $arg8, $arg9, $arg10)")
  public static @Unsigned long ZSTD_compressSeqStore_singleBlock(Ptr<ZSTD_CCtx_s> zc,
      Ptr<SeqStore_t> seqStore, Ptr<@OriginalName("Repcodes_t") repcodes_s> dRep,
      Ptr<@OriginalName("Repcodes_t") repcodes_s> cRep, Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<?> src, @Unsigned long srcSize, @Unsigned int lastBlock, @Unsigned int isPartition) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSequences($arg1, $arg2, $arg3, (const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg4, $arg5, (const void*)$arg6, $arg7)")
  public static @Unsigned long ZSTD_compressSequences(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<ZSTD_Sequence> inSeqs, @Unsigned long inSeqsSize, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSequencesAndLiterals($arg1, $arg2, $arg3, (const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg4, $arg5, (const void*)$arg6, $arg7, $arg8, $arg9)")
  public static @Unsigned long ZSTD_compressSequencesAndLiterals(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<ZSTD_Sequence> inSeqs, @Unsigned long inSeqsSize,
      Ptr<?> literals, @Unsigned long litSize, @Unsigned long litCapacity,
      @Unsigned long decompressedSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSequencesAndLiterals_internal($arg1, $arg2, $arg3, (const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg4, $arg5, (const void*)$arg6, $arg7, $arg8)")
  public static @Unsigned long ZSTD_compressSequencesAndLiterals_internal(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<?> dst, @Unsigned long dstCapacity, Ptr<ZSTD_Sequence> inSeqs, @Unsigned long nbSequences,
      Ptr<?> literals, @Unsigned long litSize, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSequences_internal($arg1, $arg2, $arg3, (const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg4, $arg5, (const void*)$arg6, $arg7)")
  public static @Unsigned long ZSTD_compressSequences_internal(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<ZSTD_Sequence> inSeqs, @Unsigned long inSeqsSize, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_compressStream(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, Ptr<ZSTD_outBuffer_s> output,
      Ptr<ZSTD_inBuffer_s> input) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_compressStream2(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_outBuffer_s> output, Ptr<ZSTD_inBuffer_s> input,
      @OriginalName("ZSTD_EndDirective") ZSTD_e endOp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressStream2_simpleArgs($arg1, $arg2, $arg3, $arg4, (const void*)$arg5, $arg6, $arg7, $arg8)")
  public static @Unsigned long ZSTD_compressStream2_simpleArgs(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<java.lang. @Unsigned Long> dstPos, Ptr<?> src,
      @Unsigned long srcSize, Ptr<java.lang. @Unsigned Long> srcPos,
      @OriginalName("ZSTD_EndDirective") ZSTD_e endOp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressStream_generic($arg1, $arg2, $arg3, (const ZSTD_e)$arg4)")
  public static @Unsigned long ZSTD_compressStream_generic(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, Ptr<ZSTD_outBuffer_s> output,
      Ptr<ZSTD_inBuffer_s> input, @OriginalName("ZSTD_EndDirective") ZSTD_e flushMode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSubBlock((const struct {\n"
          + "  struct {\n"
          + "    long unsigned int CTable[257];\n"
          + "    repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "  } huf;\n"
          + "  struct {\n"
          + "    unsigned int offcodeCTable[193];\n"
          + "    unsigned int matchlengthCTable[363];\n"
          + "    unsigned int litlengthCTable[329];\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;\n"
          + "  } fse;\n"
          + "}*)$arg1, (const struct {\n"
          + "  struct {\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t hType;\n"
          + "    u8 hufDesBuffer[128];\n"
          + "    long unsigned int hufDesSize;\n"
          + "  } hufMetadata;\n"
          + "  struct {\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t llType;\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t ofType;\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t mlType;\n"
          + "    u8 fseTablesBuffer[133];\n"
          + "    long unsigned int fseTablesSize;\n"
          + "    long unsigned int lastCountSize;\n"
          + "  } fseMetadata;\n"
          + "}*)$arg2, (const SeqDef_s*)$arg3, $arg4, (const u8*)$arg5, $arg6, (const u8*)$arg7, (const u8*)$arg8, (const u8*)$arg9, (const ZSTD_CCtx_params_s*)$arg10, $arg11, $arg12, (const int)$arg13, $arg14, $arg15, $arg16, $arg17, $arg18)")
  public static @Unsigned long ZSTD_compressSubBlock(Ptr<ZSTD_entropyCTables_t> entropy,
      Ptr<ZSTD_entropyCTablesMetadata_t> entropyMetadata, Ptr<SeqDef_s> sequences,
      @Unsigned long nbSeq, Ptr<java.lang. @OriginalName("BYTE") Character> literals,
      @Unsigned long litSize, Ptr<java.lang. @OriginalName("BYTE") Character> llCode,
      Ptr<java.lang. @OriginalName("BYTE") Character> mlCode,
      Ptr<java.lang. @OriginalName("BYTE") Character> ofCode, Ptr<ZSTD_CCtx_params_s> cctxParams,
      Ptr<?> dst, @Unsigned long dstCapacity, int bmi2, int writeLitEntropy, int writeSeqEntropy,
      Ptr<java.lang.Integer> litEntropyWritten, Ptr<java.lang.Integer> seqEntropyWritten,
      @Unsigned int lastBlock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSubBlock_literal((const long unsigned int*)$arg1, (const struct {\n"
          + "  hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t hType;\n"
          + "  u8 hufDesBuffer[128];\n"
          + "  long unsigned int hufDesSize;\n"
          + "}*)$arg2, (const u8*)$arg3, $arg4, $arg5, $arg6, (const int)$arg7, $arg8, $arg9)")
  public static @Unsigned long ZSTD_compressSubBlock_literal(
      Ptr<java.lang. @Unsigned @OriginalName("HUF_CElt") Long> hufTable,
      Ptr<ZSTD_hufCTablesMetadata_t> hufMetadata,
      Ptr<java.lang. @OriginalName("BYTE") Character> literals, @Unsigned long litSize, Ptr<?> dst,
      @Unsigned long dstSize, int bmi2, int writeEntropy, Ptr<java.lang.Integer> entropyWritten) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSubBlock_multi((const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg1, (const struct {\n"
          + "  struct {\n"
          + "    struct {\n"
          + "      long unsigned int CTable[257];\n"
          + "      repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "    } huf;\n"
          + "    struct {\n"
          + "      unsigned int offcodeCTable[193];\n"
          + "      unsigned int matchlengthCTable[363];\n"
          + "      unsigned int litlengthCTable[329];\n"
          + "      litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;\n"
          + "      litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;\n"
          + "      litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;\n"
          + "    } fse;\n"
          + "  } entropy;\n"
          + "  unsigned int rep[3];\n"
          + "}*)$arg2, $arg3, (const struct {\n"
          + "  struct {\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t hType;\n"
          + "    u8 hufDesBuffer[128];\n"
          + "    long unsigned int hufDesSize;\n"
          + "  } hufMetadata;\n"
          + "  struct {\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t llType;\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t ofType;\n"
          + "    hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t mlType;\n"
          + "    u8 fseTablesBuffer[133];\n"
          + "    long unsigned int fseTablesSize;\n"
          + "    long unsigned int lastCountSize;\n"
          + "  } fseMetadata;\n"
          + "}*)$arg4, (const ZSTD_CCtx_params_s*)$arg5, $arg6, $arg7, (const void*)$arg8, $arg9, (const int)$arg10, $arg11, $arg12, $arg13)")
  public static @Unsigned long ZSTD_compressSubBlock_multi(Ptr<SeqStore_t> seqStorePtr,
      Ptr<ZSTD_compressedBlockState_t> prevCBlock, Ptr<ZSTD_compressedBlockState_t> nextCBlock,
      Ptr<ZSTD_entropyCTablesMetadata_t> entropyMetadata, Ptr<ZSTD_CCtx_params_s> cctxParams,
      Ptr<?> dst, @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, int bmi2,
      @Unsigned int lastBlock, Ptr<?> workspace, @Unsigned long wkspSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compressSuperBlock($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6)")
  public static @Unsigned long ZSTD_compressSuperBlock(Ptr<ZSTD_CCtx_s> zc, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, @Unsigned int lastBlock) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress_advanced($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const void*)$arg6, $arg7, $arg8)")
  public static @Unsigned long ZSTD_compress_advanced(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<?> dict,
      @Unsigned long dictSize, ZSTD_parameters params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress_advanced_internal($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const void*)$arg6, $arg7, (const ZSTD_CCtx_params_s*)$arg8)")
  public static @Unsigned long ZSTD_compress_advanced_internal(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<?> dict,
      @Unsigned long dictSize, Ptr<ZSTD_CCtx_params_s> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress_frameChunk($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6)")
  public static @Unsigned long ZSTD_compress_frameChunk(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize,
      @Unsigned int lastFrameChunk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress_insertDictionary($arg1, $arg2, $arg3, $arg4, (const ZSTD_CCtx_params_s*)$arg5, (const void*)$arg6, $arg7, $arg8, $arg9, $arg10, $arg11)")
  public static @Unsigned long ZSTD_compress_insertDictionary(Ptr<ZSTD_compressedBlockState_t> bs,
      Ptr<ZSTD_MatchState_t> ms, Ptr<ldmState_t> ls, Ptr<ZSTD_cwksp> ws,
      Ptr<ZSTD_CCtx_params_s> params, Ptr<?> dict, @Unsigned long dictSize,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm,
      @OriginalName("ZSTD_tableFillPurpose_e") ZSTD_tfp_forC tfp, Ptr<?> workspace) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress_usingCDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const ZSTD_CDict_s*)$arg6)")
  public static @Unsigned long ZSTD_compress_usingCDict(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress_usingCDict_advanced($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const ZSTD_CDict_s*)$arg6, $arg7)")
  public static @Unsigned long ZSTD_compress_usingCDict_advanced(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<ZSTD_CDict_s> cdict,
      ZSTD_frameParameters fParams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_compress_usingDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const void*)$arg6, $arg7, $arg8)")
  public static @Unsigned long ZSTD_compress_usingDict(Ptr<ZSTD_CCtx_s> cctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<?> dict,
      @Unsigned long dictSize, int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_convertBlockSequences($arg1, (const const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg2, $arg3, $arg4)")
  public static @Unsigned long ZSTD_convertBlockSequences(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_Sequence> inSeqs, @Unsigned long nbSequences, int repcodeResolution) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_copyBlockSequences($arg1, (const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg2, (const unsigned int*)$arg3)")
  public static @Unsigned long ZSTD_copyBlockSequences(Ptr<SeqCollector> seqCollector,
      Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> prevRepcodes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_copyCCtx($arg1, (const ZSTD_CCtx_s*)$arg2, $arg3)")
  public static @Unsigned long ZSTD_copyCCtx(Ptr<ZSTD_CCtx_s> dstCCtx, Ptr<ZSTD_CCtx_s> srcCCtx,
      @Unsigned long pledgedSrcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_copyCCtx_internal($arg1, (const ZSTD_CCtx_s*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_copyCCtx_internal(Ptr<ZSTD_CCtx_s> dstCCtx,
      Ptr<ZSTD_CCtx_s> srcCCtx, ZSTD_frameParameters fParams, @Unsigned long pledgedSrcSize,
      @OriginalName("ZSTD_buffered_policy_e") bufferedPolicy_of_ZSTD_CCtx_and_bufferedPolicy_of_ZSTD_CCtx_s zbuff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_copyDCtx($arg1, (const ZSTD_DCtx_s*)$arg2)")
  public static void ZSTD_copyDCtx(Ptr<ZSTD_DCtx_s> dstDCtx, Ptr<ZSTD_DCtx_s> srcDCtx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_copyDDictParameters($arg1, (const ZSTD_DDict_s*)$arg2)")
  public static void ZSTD_copyDDictParameters(Ptr<ZSTD_DCtx_s> dctx, Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_count((const u8*)$arg1, (const u8*)$arg2, (const const u8*)$arg3)")
  public static @Unsigned long ZSTD_count(Ptr<java.lang. @OriginalName("BYTE") Character> pIn,
      Ptr<java.lang. @OriginalName("BYTE") Character> pMatch,
      Ptr<java.lang. @OriginalName("BYTE") Character> pInLimit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_count_2segments((const u8*)$arg1, (const u8*)$arg2, (const u8*)$arg3, (const u8*)$arg4, (const u8*)$arg5)")
  public static @Unsigned long ZSTD_count_2segments(
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> match,
      Ptr<java.lang. @OriginalName("BYTE") Character> iEnd,
      Ptr<java.lang. @OriginalName("BYTE") Character> mEnd,
      Ptr<java.lang. @OriginalName("BYTE") Character> iStart) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ZSTD_CCtx_s> ZSTD_createCCtx() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ZSTD_CCtx_params_s> ZSTD_createCCtxParams() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ZSTD_CCtx_s> ZSTD_createCCtx_advanced(ZSTD_customMem customMem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_createCDict((const void*)$arg1, $arg2, $arg3)")
  public static Ptr<ZSTD_CDict_s> ZSTD_createCDict(Ptr<?> dict, @Unsigned long dictSize,
      int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_createCDict_advanced((const void*)$arg1, $arg2, $arg3, $arg4, $arg5, $arg6)")
  public static Ptr<ZSTD_CDict_s> ZSTD_createCDict_advanced(Ptr<?> dictBuffer,
      @Unsigned long dictSize, @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      ZSTD_compressionParameters cParams, ZSTD_customMem customMem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_createCDict_advanced2((const void*)$arg1, $arg2, $arg3, $arg4, (const ZSTD_CCtx_params_s*)$arg5, $arg6)")
  public static Ptr<ZSTD_CDict_s> ZSTD_createCDict_advanced2(Ptr<?> dict, @Unsigned long dictSize,
      @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      Ptr<ZSTD_CCtx_params_s> originalCctxParams, ZSTD_customMem customMem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_createCDict_byReference((const void*)$arg1, $arg2, $arg3)")
  public static Ptr<ZSTD_CDict_s> ZSTD_createCDict_byReference(Ptr<?> dict, @Unsigned long dictSize,
      int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> ZSTD_createCStream() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> ZSTD_createCStream_advanced(
      ZSTD_customMem customMem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ZSTD_DCtx_s> ZSTD_createDCtx() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ZSTD_DCtx_s> ZSTD_createDCtx_advanced(ZSTD_customMem customMem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_createDDict((const void*)$arg1, $arg2)")
  public static Ptr<ZSTD_DDict_s> ZSTD_createDDict(Ptr<?> dict, @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_createDDict_advanced((const void*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static Ptr<ZSTD_DDict_s> ZSTD_createDDict_advanced(Ptr<?> dict, @Unsigned long dictSize,
      @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      ZSTD_customMem customMem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_createDDict_byReference((const void*)$arg1, $arg2)")
  public static Ptr<ZSTD_DDict_s> ZSTD_createDDict_byReference(Ptr<?> dictBuffer,
      @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> ZSTD_createDStream() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> ZSTD_createDStream_advanced(
      ZSTD_customMem customMem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_crossEntropyCost((const short int*)$arg1, $arg2, (const unsigned int*)$arg3, (const unsigned int)$arg4)")
  public static @Unsigned long ZSTD_crossEntropyCost(Ptr<java.lang.Short> norm,
      @Unsigned int accuracyLog, Ptr<java.lang. @Unsigned Integer> count, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ZSTD_cycleLog(@Unsigned int hashLog,
      @OriginalName("ZSTD_strategy") strategy_of_ZSTD_compressionParameters strat) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static ZSTD_bounds ZSTD_dParam_getBounds(@OriginalName("ZSTD_dParameter") ZSTD_d dParam) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decodeFrameHeader($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned long ZSTD_decodeFrameHeader(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> src,
      @Unsigned long headerSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decodeLiteralsBlock($arg1, (const void*)$arg2, $arg3, $arg4, $arg5, (const streaming_operation)$arg6)")
  public static @Unsigned long ZSTD_decodeLiteralsBlock(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> src,
      @Unsigned long srcSize, Ptr<?> dst, @Unsigned long dstCapacity,
      streaming_operation streaming) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decodeLiteralsBlock_wrapper($arg1, (const void*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_decodeLiteralsBlock_wrapper(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> src,
      @Unsigned long srcSize, Ptr<?> dst, @Unsigned long dstCapacity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decodeSeqHeaders($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static @Unsigned long ZSTD_decodeSeqHeaders(Ptr<ZSTD_DCtx_s> dctx,
      Ptr<java.lang.Integer> nbSeqPtr, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_decodingBufferSize_min(@Unsigned long windowSize,
      @Unsigned long frameContentSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompress($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static @Unsigned long ZSTD_decompress(Ptr<?> dst, @Unsigned long dstCapacity, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_decompressBegin(Ptr<ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressBegin_usingDDict($arg1, (const ZSTD_DDict_s*)$arg2)")
  public static @Unsigned long ZSTD_decompressBegin_usingDDict(Ptr<ZSTD_DCtx_s> dctx,
      Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressBegin_usingDict($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned long ZSTD_decompressBegin_usingDict(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dict,
      @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressBlock($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_decompressBlock(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressBlock_deprecated($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_decompressBlock_deprecated(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressBlock_internal($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const streaming_operation)$arg6)")
  public static @Unsigned long ZSTD_decompressBlock_internal(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize,
      streaming_operation streaming) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressBound((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_decompressBound(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressContinue($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_decompressContinue(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressContinueStream($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_decompressContinueStream(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> zds, Ptr<String> op, String oend, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressDCtx($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_decompressDCtx(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressFrame($arg1, $arg2, $arg3, (const void**)$arg4, $arg5)")
  public static @Unsigned long ZSTD_decompressFrame(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<Ptr<?>> srcPtr, Ptr<java.lang. @Unsigned Long> srcSizePtr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressMultiFrame($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const void*)$arg6, $arg7, (const ZSTD_DDict_s*)$arg8)")
  public static @Unsigned long ZSTD_decompressMultiFrame(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<?> dict,
      @Unsigned long dictSize, Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressSequencesLong_bmi2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, (const ZSTD_lo_is)$arg7)")
  public static @Unsigned long ZSTD_decompressSequencesLong_bmi2(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long maxDstSize, Ptr<?> seqStart, @Unsigned long seqSize, int nbSeq,
      @OriginalName("ZSTD_longOffset_e") ZSTD_lo_is isLongOffset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressSequencesLong_default($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, (const ZSTD_lo_is)$arg7)")
  public static @Unsigned long ZSTD_decompressSequencesLong_default(Ptr<ZSTD_DCtx_s> dctx,
      Ptr<?> dst, @Unsigned long maxDstSize, Ptr<?> seqStart, @Unsigned long seqSize, int nbSeq,
      @OriginalName("ZSTD_longOffset_e") ZSTD_lo_is isLongOffset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressSequencesSplitLitBuffer_bmi2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, (const ZSTD_lo_is)$arg7)")
  public static @Unsigned long ZSTD_decompressSequencesSplitLitBuffer_bmi2(Ptr<ZSTD_DCtx_s> dctx,
      Ptr<?> dst, @Unsigned long maxDstSize, Ptr<?> seqStart, @Unsigned long seqSize, int nbSeq,
      @OriginalName("ZSTD_longOffset_e") ZSTD_lo_is isLongOffset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressSequencesSplitLitBuffer_default($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, (const ZSTD_lo_is)$arg7)")
  public static @Unsigned long ZSTD_decompressSequencesSplitLitBuffer_default(Ptr<ZSTD_DCtx_s> dctx,
      Ptr<?> dst, @Unsigned long maxDstSize, Ptr<?> seqStart, @Unsigned long seqSize, int nbSeq,
      @OriginalName("ZSTD_longOffset_e") ZSTD_lo_is isLongOffset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressSequences_bmi2($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, (const ZSTD_lo_is)$arg7)")
  public static @Unsigned long ZSTD_decompressSequences_bmi2(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long maxDstSize, Ptr<?> seqStart, @Unsigned long seqSize, int nbSeq,
      @OriginalName("ZSTD_longOffset_e") ZSTD_lo_is isLongOffset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressSequences_default($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, $arg6, (const ZSTD_lo_is)$arg7)")
  public static @Unsigned long ZSTD_decompressSequences_default(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long maxDstSize, Ptr<?> seqStart, @Unsigned long seqSize, int nbSeq,
      @OriginalName("ZSTD_longOffset_e") ZSTD_lo_is isLongOffset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_decompressStream(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> zds, Ptr<ZSTD_outBuffer_s> output,
      Ptr<ZSTD_inBuffer_s> input) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressStream_simpleArgs($arg1, $arg2, $arg3, $arg4, (const void*)$arg5, $arg6, $arg7)")
  public static @Unsigned long ZSTD_decompressStream_simpleArgs(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<java.lang. @Unsigned Long> dstPos, Ptr<?> src,
      @Unsigned long srcSize, Ptr<java.lang. @Unsigned Long> srcPos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompress_usingDDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const ZSTD_DDict_s*)$arg6)")
  public static @Unsigned long ZSTD_decompress_usingDDict(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompress_usingDict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const void*)$arg6, $arg7)")
  public static @Unsigned long ZSTD_decompress_usingDict(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> src, @Unsigned long srcSize, Ptr<?> dict,
      @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_decompressionMargin((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_decompressionMargin(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_dedicatedDictSearch_lazy_loadDictionary($arg1, (const const u8*)$arg2)")
  public static void ZSTD_dedicatedDictSearch_lazy_loadDictionary(Ptr<ZSTD_MatchState_t> ms,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ZSTD_defaultCLevel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_deriveBlockSplitsHelper($arg1, $arg2, $arg3, $arg4, (const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg5)")
  public static void ZSTD_deriveBlockSplitsHelper(Ptr<seqStoreSplits> splits,
      @Unsigned long startIdx, @Unsigned long endIdx, Ptr<ZSTD_CCtx_s> zc,
      Ptr<SeqStore_t> origSeqStore) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_deriveSeqStoreChunk($arg1, (const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg2, $arg3, $arg4)")
  public static void ZSTD_deriveSeqStoreChunk(Ptr<SeqStore_t> resultSeqStore,
      Ptr<SeqStore_t> originalSeqStore, @Unsigned long startIdx, @Unsigned long endIdx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_encodeSequences($arg1, $arg2, (const unsigned int*)$arg3, (const u8*)$arg4, (const unsigned int*)$arg5, (const u8*)$arg6, (const unsigned int*)$arg7, (const u8*)$arg8, (const SeqDef_s*)$arg9, $arg10, $arg11, $arg12)")
  public static @Unsigned long ZSTD_encodeSequences(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_MatchLength,
      Ptr<java.lang. @OriginalName("BYTE") Character> mlCodeTable,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_OffsetBits,
      Ptr<java.lang. @OriginalName("BYTE") Character> ofCodeTable,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_LitLength,
      Ptr<java.lang. @OriginalName("BYTE") Character> llCodeTable, Ptr<SeqDef_s> sequences,
      @Unsigned long nbSeq, int longOffsets, int bmi2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_encodeSequences_bmi2($arg1, $arg2, (const unsigned int*)$arg3, (const u8*)$arg4, (const unsigned int*)$arg5, (const u8*)$arg6, (const unsigned int*)$arg7, (const u8*)$arg8, (const SeqDef_s*)$arg9, $arg10, $arg11)")
  public static @Unsigned long ZSTD_encodeSequences_bmi2(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_MatchLength,
      Ptr<java.lang. @OriginalName("BYTE") Character> mlCodeTable,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_OffsetBits,
      Ptr<java.lang. @OriginalName("BYTE") Character> ofCodeTable,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_LitLength,
      Ptr<java.lang. @OriginalName("BYTE") Character> llCodeTable, Ptr<SeqDef_s> sequences,
      @Unsigned long nbSeq, int longOffsets) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_encodeSequences_default($arg1, $arg2, (const unsigned int*)$arg3, (const u8*)$arg4, (const unsigned int*)$arg5, (const u8*)$arg6, (const unsigned int*)$arg7, (const u8*)$arg8, (const SeqDef_s*)$arg9, $arg10, $arg11)")
  public static @Unsigned long ZSTD_encodeSequences_default(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_MatchLength,
      Ptr<java.lang. @OriginalName("BYTE") Character> mlCodeTable,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_OffsetBits,
      Ptr<java.lang. @OriginalName("BYTE") Character> ofCodeTable,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> CTable_LitLength,
      Ptr<java.lang. @OriginalName("BYTE") Character> llCodeTable, Ptr<SeqDef_s> sequences,
      @Unsigned long nbSeq, int longOffsets) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_endStream(Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs,
      Ptr<ZSTD_outBuffer_s> output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_entropyCompressSeqStore_internal($arg1, $arg2, (const void*)$arg3, $arg4, (const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg5, (const struct {\n"
          + "  struct {\n"
          + "    long unsigned int CTable[257];\n"
          + "    repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "  } huf;\n"
          + "  struct {\n"
          + "    unsigned int offcodeCTable[193];\n"
          + "    unsigned int matchlengthCTable[363];\n"
          + "    unsigned int litlengthCTable[329];\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;\n"
          + "  } fse;\n"
          + "}*)$arg6, $arg7, (const ZSTD_CCtx_params_s*)$arg8, $arg9, $arg10, (const int)$arg11)")
  public static @Unsigned long ZSTD_entropyCompressSeqStore_internal(Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> literals, @Unsigned long litSize,
      Ptr<SeqStore_t> seqStorePtr, Ptr<ZSTD_entropyCTables_t> prevEntropy,
      Ptr<ZSTD_entropyCTables_t> nextEntropy, Ptr<ZSTD_CCtx_params_s> cctxParams,
      Ptr<?> entropyWorkspace, @Unsigned long entropyWkspSize, int bmi2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_entropyCompressSeqStore_wExtLitBuffer($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, (const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg6, (const struct {\n"
          + "  struct {\n"
          + "    long unsigned int CTable[257];\n"
          + "    repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "  } huf;\n"
          + "  struct {\n"
          + "    unsigned int offcodeCTable[193];\n"
          + "    unsigned int matchlengthCTable[363];\n"
          + "    unsigned int litlengthCTable[329];\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;\n"
          + "  } fse;\n"
          + "}*)$arg7, $arg8, (const ZSTD_CCtx_params_s*)$arg9, $arg10, $arg11, $arg12)")
  public static @Unsigned long ZSTD_entropyCompressSeqStore_wExtLitBuffer(Ptr<?> dst,
      @Unsigned long dstCapacity, Ptr<?> literals, @Unsigned long litSize, @Unsigned long blockSize,
      Ptr<SeqStore_t> seqStorePtr, Ptr<ZSTD_entropyCTables_t> prevEntropy,
      Ptr<ZSTD_entropyCTables_t> nextEntropy, Ptr<ZSTD_CCtx_params_s> cctxParams,
      Ptr<?> entropyWorkspace, @Unsigned long entropyWkspSize, int bmi2) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateCCtxSize(int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_estimateCCtxSize_usingCCtxParams((const ZSTD_CCtx_params_s*)$arg1)")
  public static @Unsigned long ZSTD_estimateCCtxSize_usingCCtxParams(
      Ptr<ZSTD_CCtx_params_s> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_estimateCCtxSize_usingCCtxParams_internal((const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg1, (const struct {\n"
          + "  enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s enableLdm;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int bucketSizeLog;\n"
          + "  unsigned int minMatchLength;\n"
          + "  unsigned int hashRateLog;\n"
          + "  unsigned int windowLog;\n"
          + "}*)$arg2, (const int)$arg3, (const enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s)$arg4, (const long unsigned int)$arg5, (const long unsigned int)$arg6, (const long long unsigned int)$arg7, $arg8, $arg9)")
  public static @Unsigned long ZSTD_estimateCCtxSize_usingCCtxParams_internal(
      Ptr<ZSTD_compressionParameters> cParams, Ptr<ldmParams_t> ldmParams, int isStatic,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s useRowMatchFinder,
      @Unsigned long buffInSize, @Unsigned long buffOutSize, @Unsigned long pledgedSrcSize,
      int useSequenceProducer, @Unsigned long maxBlockSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateCCtxSize_usingCParams(
      ZSTD_compressionParameters cParams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateCDictSize(@Unsigned long dictSize,
      int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateCDictSize_advanced(@Unsigned long dictSize,
      ZSTD_compressionParameters cParams,
      @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateCStreamSize(int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_estimateCStreamSize_usingCCtxParams((const ZSTD_CCtx_params_s*)$arg1)")
  public static @Unsigned long ZSTD_estimateCStreamSize_usingCCtxParams(
      Ptr<ZSTD_CCtx_params_s> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateCStreamSize_usingCParams(
      ZSTD_compressionParameters cParams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateDCtxSize() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateDDictSize(@Unsigned long dictSize,
      @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_estimateDStreamSize(@Unsigned long windowSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_estimateDStreamSize_fromFrame((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_estimateDStreamSize_fromFrame(Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_estimateSubBlockSize_symbolType($arg1, (const u8*)$arg2, $arg3, $arg4, (const unsigned int*)$arg5, (const u8*)$arg6, (const short int*)$arg7, $arg8, $arg9, $arg10, $arg11)")
  public static @Unsigned long ZSTD_estimateSubBlockSize_symbolType(
      @OriginalName("SymbolEncodingType_e") hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t type,
      Ptr<java.lang. @OriginalName("BYTE") Character> codeTable, @Unsigned int maxCode,
      @Unsigned long nbSeq, Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> fseCTable,
      Ptr<java.lang.Character> additionalBits, Ptr<java.lang.Short> defaultNorm,
      @Unsigned int defaultNormLog, @Unsigned int defaultMax, Ptr<?> workspace,
      @Unsigned long wkspSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_execSequenceEnd($arg1, (const u8*)$arg2, $arg3, (const u8**)$arg4, (const const u8*)$arg5, (const const u8*)$arg6, (const const u8*)$arg7, (const const u8*)$arg8)")
  public static @Unsigned long ZSTD_execSequenceEnd(
      Ptr<java.lang. @OriginalName("BYTE") Character> op,
      Ptr<java.lang. @OriginalName("BYTE") Character> oend, seq_t sequence,
      Ptr<Ptr<java.lang. @OriginalName("BYTE") Character>> litPtr,
      Ptr<java.lang. @OriginalName("BYTE") Character> litLimit,
      Ptr<java.lang. @OriginalName("BYTE") Character> prefixStart,
      Ptr<java.lang. @OriginalName("BYTE") Character> virtualStart,
      Ptr<java.lang. @OriginalName("BYTE") Character> dictEnd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_execSequenceEndSplitLitBuffer($arg1, (const u8*)$arg2, (const const u8*)$arg3, $arg4, (const u8**)$arg5, (const const u8*)$arg6, (const const u8*)$arg7, (const const u8*)$arg8, (const const u8*)$arg9)")
  public static @Unsigned long ZSTD_execSequenceEndSplitLitBuffer(
      Ptr<java.lang. @OriginalName("BYTE") Character> op,
      Ptr<java.lang. @OriginalName("BYTE") Character> oend,
      Ptr<java.lang. @OriginalName("BYTE") Character> oend_w, seq_t sequence,
      Ptr<Ptr<java.lang. @OriginalName("BYTE") Character>> litPtr,
      Ptr<java.lang. @OriginalName("BYTE") Character> litLimit,
      Ptr<java.lang. @OriginalName("BYTE") Character> prefixStart,
      Ptr<java.lang. @OriginalName("BYTE") Character> virtualStart,
      Ptr<java.lang. @OriginalName("BYTE") Character> dictEnd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_fillDoubleHashTable($arg1, (const const void*)$arg2, $arg3, $arg4)")
  public static void ZSTD_fillDoubleHashTable(Ptr<ZSTD_MatchState_t> ms, Ptr<?> end,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm,
      @OriginalName("ZSTD_tableFillPurpose_e") ZSTD_tfp_forC tfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_fillDoubleHashTableForCCtx($arg1, (const void*)$arg2, $arg3)")
  public static void ZSTD_fillDoubleHashTableForCCtx(Ptr<ZSTD_MatchState_t> ms, Ptr<?> end,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_fillDoubleHashTableForCDict($arg1, (const void*)$arg2, $arg3)")
  public static void ZSTD_fillDoubleHashTableForCDict(Ptr<ZSTD_MatchState_t> ms, Ptr<?> end,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_fillHashTable($arg1, (const const void*)$arg2, $arg3, $arg4)")
  public static void ZSTD_fillHashTable(Ptr<ZSTD_MatchState_t> ms, Ptr<?> end,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm,
      @OriginalName("ZSTD_tableFillPurpose_e") ZSTD_tfp_forC tfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_fillHashTableForCCtx($arg1, (const const void*)$arg2, $arg3)")
  public static void ZSTD_fillHashTableForCCtx(Ptr<ZSTD_MatchState_t> ms, Ptr<?> end,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_fillHashTableForCDict($arg1, (const const void*)$arg2, $arg3)")
  public static void ZSTD_fillHashTableForCDict(Ptr<ZSTD_MatchState_t> ms, Ptr<?> end,
      @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_findDecompressedSize((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_findDecompressedSize(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_findFrameCompressedSize((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_findFrameCompressedSize(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_flushStream(Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs,
      Ptr<ZSTD_outBuffer_s> output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_frameHeaderSize((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_frameHeaderSize(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_frameHeaderSize_internal((const void*)$arg1, $arg2, $arg3)")
  public static @Unsigned long ZSTD_frameHeaderSize_internal(Ptr<?> src, @Unsigned long srcSize,
      @OriginalName("ZSTD_format_e") format_of_ZSTD_CCtx_params_and_format_of_ZSTD_CCtx_params_s_and_format_of_ZSTD_DCtx format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_freeCCtx(Ptr<ZSTD_CCtx_s> cctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_freeCCtxParams(Ptr<ZSTD_CCtx_params_s> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_freeCDict(Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_freeCStream(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_freeDCtx(Ptr<ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_freeDDict(Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_freeDStream(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> zds) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_fseBitCost((const unsigned int*)$arg1, (const unsigned int*)$arg2, (const unsigned int)$arg3)")
  public static @Unsigned long ZSTD_fseBitCost(
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> ctable,
      Ptr<java.lang. @Unsigned Integer> count, @Unsigned int max) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_generateSequences($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_generateSequences(Ptr<ZSTD_CCtx_s> zc,
      Ptr<ZSTD_Sequence> outSeqs, @Unsigned long outSeqsSize, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getBlockSize((const ZSTD_CCtx_s*)$arg1)")
  public static @Unsigned long ZSTD_getBlockSize(Ptr<ZSTD_CCtx_s> cctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getDecompressedSize((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_getDecompressedSize(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getDictID_fromCDict((const ZSTD_CDict_s*)$arg1)")
  public static @Unsigned int ZSTD_getDictID_fromCDict(Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getDictID_fromDDict((const ZSTD_DDict_s*)$arg1)")
  public static @Unsigned int ZSTD_getDictID_fromDDict(Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getDictID_fromDict((const void*)$arg1, $arg2)")
  public static @Unsigned int ZSTD_getDictID_fromDict(Ptr<?> dict, @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getDictID_fromFrame((const void*)$arg1, $arg2)")
  public static @Unsigned int ZSTD_getDictID_fromFrame(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ZSTD_ErrorCode") ZSTD_error ZSTD_getErrorCode(@Unsigned long code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ZSTD_getErrorName($arg1))")
  public static String ZSTD_getErrorName(@Unsigned long code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ZSTD_getErrorString($arg1))")
  public static String ZSTD_getErrorString(@OriginalName("ZSTD_ErrorCode") ZSTD_error code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getFrameContentSize((const void*)$arg1, $arg2)")
  public static @Unsigned long ZSTD_getFrameContentSize(Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getFrameHeader($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned long ZSTD_getFrameHeader(Ptr<ZSTD_FrameHeader> zfhPtr, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getFrameHeader_advanced($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static @Unsigned long ZSTD_getFrameHeader_advanced(Ptr<ZSTD_FrameHeader> zfhPtr,
      Ptr<?> src, @Unsigned long srcSize,
      @OriginalName("ZSTD_format_e") format_of_ZSTD_CCtx_params_and_format_of_ZSTD_CCtx_params_s_and_format_of_ZSTD_DCtx format) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)ZSTD_getSeqStore((const ZSTD_CCtx_s*)$arg1))")
  public static Ptr<SeqStore_t> ZSTD_getSeqStore(Ptr<ZSTD_CCtx_s> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_getcBlockSize((const void*)$arg1, $arg2, $arg3)")
  public static @Unsigned long ZSTD_getcBlockSize(Ptr<?> src, @Unsigned long srcSize,
      Ptr<blockProperties_t> bpPtr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initCDict_internal($arg1, (const void*)$arg2, $arg3, $arg4, $arg5, $arg6)")
  public static @Unsigned long ZSTD_initCDict_internal(Ptr<ZSTD_CDict_s> cdict, Ptr<?> dictBuffer,
      @Unsigned long dictSize, @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      ZSTD_CCtx_params_s params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_initCStream(Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs,
      int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initCStream_advanced($arg1, (const void*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_initCStream_advanced(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, Ptr<?> dict, @Unsigned long dictSize,
      ZSTD_parameters params, @Unsigned long pss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initCStream_internal($arg1, (const void*)$arg2, $arg3, (const ZSTD_CDict_s*)$arg4, (const ZSTD_CCtx_params_s*)$arg5, $arg6)")
  public static @Unsigned long ZSTD_initCStream_internal(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, Ptr<?> dict, @Unsigned long dictSize,
      Ptr<ZSTD_CDict_s> cdict, Ptr<ZSTD_CCtx_params_s> params, @Unsigned long pledgedSrcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_initCStream_srcSize(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, int compressionLevel,
      @Unsigned long pss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initCStream_usingCDict($arg1, (const ZSTD_CDict_s*)$arg2)")
  public static @Unsigned long ZSTD_initCStream_usingCDict(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initCStream_usingCDict_advanced($arg1, (const ZSTD_CDict_s*)$arg2, $arg3, $arg4)")
  public static @Unsigned long ZSTD_initCStream_usingCDict_advanced(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, Ptr<ZSTD_CDict_s> cdict,
      ZSTD_frameParameters fParams, @Unsigned long pledgedSrcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initCStream_usingDict($arg1, (const void*)$arg2, $arg3, $arg4)")
  public static @Unsigned long ZSTD_initCStream_usingDict(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs, Ptr<?> dict, @Unsigned long dictSize,
      int compressionLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_initDCtx_internal(Ptr<ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initDDict_internal($arg1, (const void*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_initDDict_internal(Ptr<ZSTD_DDict_s> ddict, Ptr<?> dict,
      @Unsigned long dictSize, @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_initDStream(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> zds) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initDStream_usingDDict($arg1, (const ZSTD_DDict_s*)$arg2)")
  public static @Unsigned long ZSTD_initDStream_usingDDict(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> dctx, Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initDStream_usingDict($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned long ZSTD_initDStream_usingDict(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> zds, Ptr<?> dict, @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_initFseState($arg1, $arg2, (const struct {\n"
          + "  short unsigned int nextState;\n"
          + "  u8 nbAdditionalBits;\n"
          + "  u8 nbBits;\n"
          + "  unsigned int baseValue;\n"
          + "}*)$arg3)")
  public static void ZSTD_initFseState(Ptr<ZSTD_fseState> DStatePtr, Ptr<BIT_DStream_t> bitD,
      Ptr<ZSTD_seqSymbol> dt) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ZSTD_CCtx_s> ZSTD_initStaticCCtx(Ptr<?> workspace,
      @Unsigned long workspaceSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const ZSTD_CDict_s*)ZSTD_initStaticCDict($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6, $arg7))")
  public static Ptr<ZSTD_CDict_s> ZSTD_initStaticCDict(Ptr<?> workspace,
      @Unsigned long workspaceSize, Ptr<?> dict, @Unsigned long dictSize,
      @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType,
      ZSTD_compressionParameters cParams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> ZSTD_initStaticCStream(
      Ptr<?> workspace, @Unsigned long workspaceSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<ZSTD_DCtx_s> ZSTD_initStaticDCtx(Ptr<?> workspace,
      @Unsigned long workspaceSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const ZSTD_DDict_s*)ZSTD_initStaticDDict($arg1, $arg2, (const void*)$arg3, $arg4, $arg5, $arg6))")
  public static Ptr<ZSTD_DDict_s> ZSTD_initStaticDDict(Ptr<?> sBuffer, @Unsigned long sBufferSize,
      Ptr<?> dict, @Unsigned long dictSize,
      @OriginalName("ZSTD_dictLoadMethod_e") ZSTD_dlm_by dictLoadMethod,
      @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> ZSTD_initStaticDStream(
      Ptr<?> workspace, @Unsigned long workspaceSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_insertAndFindFirstIndex($arg1, (const u8*)$arg2)")
  public static @Unsigned int ZSTD_insertAndFindFirstIndex(Ptr<ZSTD_MatchState_t> ms,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_insertAndFindFirstIndexHash3((const ZSTD_MatchState_t*)$arg1, $arg2, (const const u8*)$arg3)")
  public static @Unsigned int ZSTD_insertAndFindFirstIndexHash3(Ptr<ZSTD_MatchState_t> ms,
      Ptr<java.lang. @Unsigned Integer> nextToUpdate3,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_insertBlock($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned long ZSTD_insertBlock(Ptr<ZSTD_DCtx_s> dctx, Ptr<?> blockStart,
      @Unsigned long blockSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_insertBt1((const ZSTD_MatchState_t*)$arg1, (const const u8*)$arg2, (const const u8*)$arg3, (const unsigned int)$arg4, (const unsigned int)$arg5, (const int)$arg6)")
  public static @Unsigned int ZSTD_insertBt1(Ptr<ZSTD_MatchState_t> ms,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iend, @Unsigned int target, @Unsigned int mls,
      int extDict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_insertDUBT1((const ZSTD_MatchState_t*)$arg1, $arg2, (const u8*)$arg3, $arg4, $arg5, (const ZSTD)$arg6)")
  public static void ZSTD_insertDUBT1(Ptr<ZSTD_MatchState_t> ms, @Unsigned int curr,
      Ptr<java.lang. @OriginalName("BYTE") Character> inputEnd, @Unsigned int nbCompares,
      @Unsigned int btLow, @OriginalName("ZSTD_dictMode_e") ZSTD dictMode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_invalidateRepCodes(Ptr<ZSTD_CCtx_s> cctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ZSTD_isError(@Unsigned long code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_isFrame((const void*)$arg1, $arg2)")
  public static @Unsigned int ZSTD_isFrame(Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_isRLE((const u8*)$arg1, $arg2)")
  public static int ZSTD_isRLE(Ptr<java.lang. @OriginalName("BYTE") Character> src,
      @Unsigned long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_isSkippableFrame((const void*)$arg1, $arg2)")
  public static @Unsigned int ZSTD_isSkippableFrame(Ptr<?> buffer, @Unsigned long size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_adjustParameters($arg1, (const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg2)")
  public static void ZSTD_ldm_adjustParameters(Ptr<ldmParams_t> params,
      Ptr<ZSTD_compressionParameters> cParams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_blockCompress($arg1, $arg2, $arg3, $arg4, $arg5, (const void*)$arg6, $arg7)")
  public static @Unsigned long ZSTD_ldm_blockCompress(Ptr<RawSeqStore_t> rawSeqStore,
      Ptr<ZSTD_MatchState_t> ms, Ptr<SeqStore_t> seqStore, Ptr<java.lang. @Unsigned Integer> rep,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s useRowMatchFinder,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_fillHashTable($arg1, (const u8*)$arg2, (const u8*)$arg3, (const struct {\n"
          + "  enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s enableLdm;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int bucketSizeLog;\n"
          + "  unsigned int minMatchLength;\n"
          + "  unsigned int hashRateLog;\n"
          + "  unsigned int windowLog;\n"
          + "}*)$arg4)")
  public static void ZSTD_ldm_fillHashTable(Ptr<ldmState_t> ldmState,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iend, Ptr<ldmParams_t> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_gear_feed($arg1, (const u8*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_ldm_gear_feed(Ptr<ldmRollingHashState_t> state,
      Ptr<java.lang. @OriginalName("BYTE") Character> data, @Unsigned long size,
      Ptr<java.lang. @Unsigned Long> splits, Ptr<java.lang. @Unsigned Integer> numSplits) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_gear_init($arg1, (const struct {\n"
          + "  enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s enableLdm;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int bucketSizeLog;\n"
          + "  unsigned int minMatchLength;\n"
          + "  unsigned int hashRateLog;\n"
          + "  unsigned int windowLog;\n"
          + "}*)$arg2)")
  public static void ZSTD_ldm_gear_init(Ptr<ldmRollingHashState_t> state, Ptr<ldmParams_t> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_generateSequences($arg1, $arg2, (const struct {\n"
          + "  enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s enableLdm;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int bucketSizeLog;\n"
          + "  unsigned int minMatchLength;\n"
          + "  unsigned int hashRateLog;\n"
          + "  unsigned int windowLog;\n"
          + "}*)$arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_ldm_generateSequences(Ptr<ldmState_t> ldmState,
      Ptr<RawSeqStore_t> sequences, Ptr<ldmParams_t> params, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_generateSequences_internal($arg1, $arg2, (const struct {\n"
          + "  enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s enableLdm;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int bucketSizeLog;\n"
          + "  unsigned int minMatchLength;\n"
          + "  unsigned int hashRateLog;\n"
          + "  unsigned int windowLog;\n"
          + "}*)$arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_ldm_generateSequences_internal(Ptr<ldmState_t> ldmState,
      Ptr<RawSeqStore_t> rawSeqStore, Ptr<ldmParams_t> params, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_ldm_getMaxNbSeq(ldmParams_t params,
      @Unsigned long maxChunkSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_ldm_getTableSize(ldmParams_t params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_insertEntry($arg1, (const long unsigned int)$arg2, (const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int checksum;\n"
          + "})$arg3, (const unsigned int)$arg4)")
  public static void ZSTD_ldm_insertEntry(Ptr<ldmState_t> ldmState, @Unsigned long hash,
      ldmEntry_t entry, @Unsigned int bucketSizeLog) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_ldm_skipRawSeqStoreBytes(Ptr<RawSeqStore_t> rawSeqStore,
      @Unsigned long nbBytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_ldm_skipSequences($arg1, $arg2, (const unsigned int)$arg3)")
  public static void ZSTD_ldm_skipSequences(Ptr<RawSeqStore_t> rawSeqStore, @Unsigned long srcSize,
      @Unsigned int minMatch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_loadCEntropy($arg1, $arg2, (const const void*)$arg3, $arg4)")
  public static @Unsigned long ZSTD_loadCEntropy(Ptr<ZSTD_compressedBlockState_t> bs,
      Ptr<?> workspace, Ptr<?> dict, @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_loadDEntropy($arg1, (const const void*)$arg2, (const long unsigned int)$arg3)")
  public static @Unsigned long ZSTD_loadDEntropy(Ptr<ZSTD_entropyDTables_t> entropy, Ptr<?> dict,
      @Unsigned long dictSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_loadDictionaryContent($arg1, $arg2, $arg3, (const ZSTD_CCtx_params_s*)$arg4, (const void*)$arg5, $arg6, $arg7, $arg8)")
  public static @Unsigned long ZSTD_loadDictionaryContent(Ptr<ZSTD_MatchState_t> ms,
      Ptr<ldmState_t> ls, Ptr<ZSTD_cwksp> ws, Ptr<ZSTD_CCtx_params_s> params, Ptr<?> src,
      @Unsigned long srcSize, @OriginalName("ZSTD_dictTableLoadMethod_e") ZSTD_dtlm_f dtlm,
      @OriginalName("ZSTD_tableFillPurpose_e") ZSTD_tfp_forC tfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static ZSTD_CCtx_params_s ZSTD_makeCCtxParamsFromCParams(
      ZSTD_compressionParameters cParams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ZSTD_maxCLevel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_mergeBlockDelimiters(Ptr<ZSTD_Sequence> sequences,
      @Unsigned long seqsSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int ZSTD_minCLevel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ZSTD_nextInputType_e") ZSTDnit ZSTD_nextInputType(
      Ptr<ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_nextSrcSizeToDecompress(Ptr<ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_noCompressLiterals($arg1, $arg2, (const void*)$arg3, $arg4)")
  public static @Unsigned long ZSTD_noCompressLiterals(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_optLdm_maybeAddMatch($arg1, $arg2, (const struct {\n"
          + "  struct {\n"
          + "    struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "} *seq;\n"
          + "    long unsigned int pos;\n"
          + "    long unsigned int posInSequence;\n"
          + "    long unsigned int size;\n"
          + "    long unsigned int capacity;\n"
          + "  } seqStore;\n"
          + "  unsigned int startPosInBlock;\n"
          + "  unsigned int endPosInBlock;\n"
          + "  unsigned int offset;\n"
          + "}*)$arg3, $arg4, $arg5)")
  public static void ZSTD_optLdm_maybeAddMatch(Ptr<ZSTD_match_t> matches,
      Ptr<java.lang. @Unsigned Integer> nbMatches, Ptr<ZSTD_optLdm_t> optLdm,
      @Unsigned int currPosInBlock, @Unsigned int minMatch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_optLdm_processMatchCandidate(Ptr<ZSTD_optLdm_t> optLdm,
      Ptr<ZSTD_match_t> matches, Ptr<java.lang. @Unsigned Integer> nbMatches,
      @Unsigned int currPosInBlock, @Unsigned int remainingBytes, @Unsigned int minMatch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_optLdm_skipRawSeqStoreBytes(Ptr<RawSeqStore_t> rawSeqStore,
      @Unsigned long nbBytes) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_opt_getNextMatchAndUpdateSeqStore(Ptr<ZSTD_optLdm_t> optLdm,
      @Unsigned int currPosInBlock, @Unsigned int blockBytesRemaining) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_overflowCorrectIfNeeded($arg1, $arg2, (const ZSTD_CCtx_params_s*)$arg3, (const void*)$arg4, (const void*)$arg5)")
  public static void ZSTD_overflowCorrectIfNeeded(Ptr<ZSTD_MatchState_t> ms, Ptr<ZSTD_cwksp> ws,
      Ptr<ZSTD_CCtx_params_s> params, Ptr<?> ip, Ptr<?> iend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_readSkippableFrame($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long ZSTD_readSkippableFrame(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<java.lang. @Unsigned Integer> magicVariant, Ptr<?> src, @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_recordFingerprint_1($arg1, (const void*)$arg2, $arg3)")
  public static void ZSTD_recordFingerprint_1(Ptr<Fingerprint> fp, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_recordFingerprint_11($arg1, (const void*)$arg2, $arg3)")
  public static void ZSTD_recordFingerprint_11(Ptr<Fingerprint> fp, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_recordFingerprint_43($arg1, (const void*)$arg2, $arg3)")
  public static void ZSTD_recordFingerprint_43(Ptr<Fingerprint> fp, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_recordFingerprint_5($arg1, (const void*)$arg2, $arg3)")
  public static void ZSTD_recordFingerprint_5(Ptr<Fingerprint> fp, Ptr<?> src,
      @Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_referenceExternalSequences(Ptr<ZSTD_CCtx_s> cctx, Ptr<rawSeq> seq,
      @Unsigned long nbSeq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_registerSequenceProducer(Ptr<ZSTD_CCtx_s> zc, Ptr<?> extSeqProdState,
      @OriginalName("ZSTD_sequenceProducer_F") Ptr<?> extSeqProdFunc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_rescaleFreqs((const struct {\n"
          + "  unsigned int *litFreq;\n"
          + "  unsigned int *litLengthFreq;\n"
          + "  unsigned int *matchLengthFreq;\n"
          + "  unsigned int *offCodeFreq;\n"
          + "  struct {\n"
          + "  unsigned int off;\n"
          + "  unsigned int len;\n"
          + "} *matchTable;\n"
          + "  struct {\n"
          + "  int price;\n"
          + "  unsigned int off;\n"
          + "  unsigned int mlen;\n"
          + "  unsigned int litlen;\n"
          + "  unsigned int rep[3];\n"
          + "} *priceTable;\n"
          + "  unsigned int litSum;\n"
          + "  unsigned int litLengthSum;\n"
          + "  unsigned int matchLengthSum;\n"
          + "  unsigned int offCodeSum;\n"
          + "  unsigned int litSumBasePrice;\n"
          + "  unsigned int litLengthSumBasePrice;\n"
          + "  unsigned int matchLengthSumBasePrice;\n"
          + "  unsigned int offCodeSumBasePrice;\n"
          + "  priceType_of_optState_t priceType;\n"
          + "const struct {\n"
          + "  struct {\n"
          + "    long unsigned int CTable[257];\n"
          + "    repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "  } huf;\n"
          + "  struct {\n"
          + "    unsigned int offcodeCTable[193];\n"
          + "    unsigned int matchlengthCTable[363];\n"
          + "    unsigned int litlengthCTable[329];\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;\n"
          + "  } fse;\n"
          + "}*;\n"
          + "  enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s literalCompressionMode;\n"
          + "}*)$arg1, (const const u8*)$arg2, (const long unsigned int)$arg3, (const int)$arg4)")
  public static void ZSTD_rescaleFreqs(Ptr<optState_t> optPtr,
      Ptr<java.lang. @OriginalName("BYTE") Character> src, @Unsigned long srcSize, int optLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_resetCCtx_byCopyingCDict($arg1, (const ZSTD_CDict_s*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_resetCCtx_byCopyingCDict(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_CDict_s> cdict, ZSTD_CCtx_params_s params, @Unsigned long pledgedSrcSize,
      @OriginalName("ZSTD_buffered_policy_e") bufferedPolicy_of_ZSTD_CCtx_and_bufferedPolicy_of_ZSTD_CCtx_s zbuff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_resetCCtx_internal($arg1, (const ZSTD_CCtx_params_s*)$arg2, (const long long unsigned int)$arg3, (const long unsigned int)$arg4, (const ZSTDcrp)$arg5, (const bufferedPolicy_of_ZSTD_CCtx_and_bufferedPolicy_of_ZSTD_CCtx_s)$arg6)")
  public static @Unsigned long ZSTD_resetCCtx_internal(Ptr<ZSTD_CCtx_s> zc,
      Ptr<ZSTD_CCtx_params_s> params, @Unsigned long pledgedSrcSize, @Unsigned long loadedDictSize,
      @OriginalName("ZSTD_compResetPolicy_e") ZSTDcrp crp,
      @OriginalName("ZSTD_buffered_policy_e") bufferedPolicy_of_ZSTD_CCtx_and_bufferedPolicy_of_ZSTD_CCtx_s zbuff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_resetCCtx_usingCDict($arg1, (const ZSTD_CDict_s*)$arg2, (const ZSTD_CCtx_params_s*)$arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_resetCCtx_usingCDict(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_CDict_s> cdict, Ptr<ZSTD_CCtx_params_s> params, @Unsigned long pledgedSrcSize,
      @OriginalName("ZSTD_buffered_policy_e") bufferedPolicy_of_ZSTD_CCtx_and_bufferedPolicy_of_ZSTD_CCtx_s zbuff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_resetCStream(Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs,
      @Unsigned long pss) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_resetDStream(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_resetSeqStore(Ptr<SeqStore_t> ssPtr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_reset_compressedBlockState(Ptr<ZSTD_compressedBlockState_t> bs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_reset_matchState($arg1, $arg2, (const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg3, (const enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s)$arg4, (const ZSTDcrp)$arg5, (const ZSTDirp)$arg6, (const ZSTD_resetTarget_C)$arg7)")
  public static @Unsigned long ZSTD_reset_matchState(Ptr<ZSTD_MatchState_t> ms, Ptr<ZSTD_cwksp> ws,
      Ptr<ZSTD_compressionParameters> cParams,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s useRowMatchFinder,
      @OriginalName("ZSTD_compResetPolicy_e") ZSTDcrp crp,
      @OriginalName("ZSTD_indexResetPolicy_e") ZSTDirp forceResetIndex,
      @OriginalName("ZSTD_resetTarget_e") ZSTD_resetTarget_C forWho) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_row_update((const ZSTD_MatchState_t*)$arg1, (const u8*)$arg2)")
  public static void ZSTD_row_update(Ptr<ZSTD_MatchState_t> ms,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_safecopy($arg1, (const const u8*)$arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void ZSTD_safecopy(Ptr<java.lang. @OriginalName("BYTE") Character> op,
      Ptr<java.lang. @OriginalName("BYTE") Character> oend_w,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip, @OriginalName("ptrdiff_t") long length,
      @OriginalName("ZSTD_overlap_e") ZSTD ovtype) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_safecopyDstBeforeSrc($arg1, (const u8*)$arg2, $arg3)")
  public static void ZSTD_safecopyDstBeforeSrc(Ptr<java.lang. @OriginalName("BYTE") Character> op,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip, @OriginalName("ptrdiff_t") long length) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_safecopyLiterals($arg1, (const u8*)$arg2, (const const u8*)$arg3, (const u8*)$arg4)")
  public static void ZSTD_safecopyLiterals(Ptr<java.lang. @OriginalName("BYTE") Character> op,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iend,
      Ptr<java.lang. @OriginalName("BYTE") Character> ilimit_w) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("ZSTD_BlockCompressor_f") Ptr<?> ZSTD_selectBlockCompressor(
      @OriginalName("ZSTD_strategy") strategy_of_ZSTD_compressionParameters strat,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s useRowMatchFinder,
      @OriginalName("ZSTD_dictMode_e") ZSTD dictMode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_selectEncodingType($arg1, (const unsigned int*)$arg2, (const unsigned int)$arg3, (const long unsigned int)$arg4, $arg5, (const unsigned int)$arg6, (const unsigned int*)$arg7, (const short int*)$arg8, $arg9, (const ZSTD_default)$arg10, (const strategy_of_ZSTD_compressionParameters)$arg11)")
  public static @OriginalName("SymbolEncodingType_e") hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t ZSTD_selectEncodingType(
      Ptr<@OriginalName("FSE_repeat") litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t> repeatMode,
      Ptr<java.lang. @Unsigned Integer> count, @Unsigned int max, @Unsigned long mostFrequent,
      @Unsigned long nbSeq, @Unsigned int FSELog,
      Ptr<java.lang. @Unsigned @OriginalName("FSE_CTable") Integer> prevCTable,
      Ptr<java.lang.Short> defaultNorm, @Unsigned int defaultNormLog,
      @OriginalName("ZSTD_DefaultPolicy_e") ZSTD_default isDefaultAllowed,
      @OriginalName("ZSTD_strategy") strategy_of_ZSTD_compressionParameters strategy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_seqStore_resolveOffCodes((const repcodes_s*)$arg1, (const repcodes_s*)$arg2, (const const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg3, (const unsigned int)$arg4)")
  public static void ZSTD_seqStore_resolveOffCodes(
      Ptr<@OriginalName("Repcodes_t") repcodes_s> dRepcodes,
      Ptr<@OriginalName("Repcodes_t") repcodes_s> cRepcodes, Ptr<SeqStore_t> seqStore,
      @Unsigned int nbSeq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_seqToCodes((const struct {\n"
          + "  SeqDef_s *sequencesStart;\n"
          + "  SeqDef_s *sequences;\n"
          + "  u8 *litStart;\n"
          + "  u8 *lit;\n"
          + "  u8 *llCode;\n"
          + "  u8 *mlCode;\n"
          + "  u8 *ofCode;\n"
          + "  long unsigned int maxNbSeq;\n"
          + "  long unsigned int maxNbLit;\n"
          + "  longLengthType_of_SeqStore_t longLengthType;\n"
          + "  unsigned int longLengthPos;\n"
          + "}*)$arg1)")
  public static int ZSTD_seqToCodes(Ptr<SeqStore_t> seqStorePtr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_sequenceBound(@Unsigned long srcSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void ZSTD_setBasePrices(Ptr<optState_t> optPtr, int optLevel) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_sizeof_CCtx((const ZSTD_CCtx_s*)$arg1)")
  public static @Unsigned long ZSTD_sizeof_CCtx(Ptr<ZSTD_CCtx_s> cctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_sizeof_CDict((const ZSTD_CDict_s*)$arg1)")
  public static @Unsigned long ZSTD_sizeof_CDict(Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_sizeof_CStream((const ZSTD_CCtx_s*)$arg1)")
  public static @Unsigned long ZSTD_sizeof_CStream(
      Ptr<@OriginalName("ZSTD_CStream") ZSTD_CCtx_s> zcs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_sizeof_DCtx((const ZSTD_DCtx_s*)$arg1)")
  public static @Unsigned long ZSTD_sizeof_DCtx(Ptr<ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_sizeof_DDict((const ZSTD_DDict_s*)$arg1)")
  public static @Unsigned long ZSTD_sizeof_DDict(Ptr<ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_sizeof_DStream((const ZSTD_DCtx_s*)$arg1)")
  public static @Unsigned long ZSTD_sizeof_DStream(
      Ptr<@OriginalName("ZSTD_DStream") ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_sizeof_matchState((const const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg1, (const enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s)$arg2, (const int)$arg3, (const unsigned int)$arg4)")
  public static @Unsigned long ZSTD_sizeof_matchState(Ptr<ZSTD_compressionParameters> cParams,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s useRowMatchFinder,
      int enableDedicatedDictSearch, @Unsigned int forCCtx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_splitBlock((const void*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_splitBlock(Ptr<?> blockStart, @Unsigned long blockSize,
      int level, Ptr<?> workspace, @Unsigned long wkspSize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_toFlushNow(Ptr<ZSTD_CCtx_s> cctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_transferSequences_noDelim($arg1, $arg2, (const const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg3, $arg4, (const void*)$arg5, $arg6, $arg7)")
  public static @Unsigned long ZSTD_transferSequences_noDelim(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_SequencePosition> seqPos, Ptr<ZSTD_Sequence> inSeqs, @Unsigned long inSeqsSize,
      Ptr<?> src, @Unsigned long blockSize,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s externalRepSearch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_transferSequences_wBlockDelim($arg1, $arg2, (const const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg3, $arg4, (const void*)$arg5, $arg6, $arg7)")
  public static @Unsigned long ZSTD_transferSequences_wBlockDelim(Ptr<ZSTD_CCtx_s> cctx,
      Ptr<ZSTD_SequencePosition> seqPos, Ptr<ZSTD_Sequence> inSeqs, @Unsigned long inSeqsSize,
      Ptr<?> src, @Unsigned long blockSize,
      @OriginalName("ZSTD_ParamSwitch_e") enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s externalRepSearch) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_updateStats((const struct {\n"
          + "  unsigned int *litFreq;\n"
          + "  unsigned int *litLengthFreq;\n"
          + "  unsigned int *matchLengthFreq;\n"
          + "  unsigned int *offCodeFreq;\n"
          + "  struct {\n"
          + "  unsigned int off;\n"
          + "  unsigned int len;\n"
          + "} *matchTable;\n"
          + "  struct {\n"
          + "  int price;\n"
          + "  unsigned int off;\n"
          + "  unsigned int mlen;\n"
          + "  unsigned int litlen;\n"
          + "  unsigned int rep[3];\n"
          + "} *priceTable;\n"
          + "  unsigned int litSum;\n"
          + "  unsigned int litLengthSum;\n"
          + "  unsigned int matchLengthSum;\n"
          + "  unsigned int offCodeSum;\n"
          + "  unsigned int litSumBasePrice;\n"
          + "  unsigned int litLengthSumBasePrice;\n"
          + "  unsigned int matchLengthSumBasePrice;\n"
          + "  unsigned int offCodeSumBasePrice;\n"
          + "  priceType_of_optState_t priceType;\n"
          + "const struct {\n"
          + "  struct {\n"
          + "    long unsigned int CTable[257];\n"
          + "    repeatMode_of_ZSTD_hufCTables_t repeatMode;\n"
          + "  } huf;\n"
          + "  struct {\n"
          + "    unsigned int offcodeCTable[193];\n"
          + "    unsigned int matchlengthCTable[363];\n"
          + "    unsigned int litlengthCTable[329];\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;\n"
          + "    litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;\n"
          + "  } fse;\n"
          + "}*;\n"
          + "  enableLdm_of_ldmParams_t_and_literalCompressionMode_of_ZSTD_CCtx_params_and_literalCompressionMode_of_ZSTD_CCtx_params_s literalCompressionMode;\n"
          + "}*)$arg1, $arg2, (const u8*)$arg3, $arg4, $arg5)")
  public static void ZSTD_updateStats(Ptr<optState_t> optPtr, @Unsigned int litLength,
      Ptr<java.lang. @OriginalName("BYTE") Character> literals, @Unsigned int offBase,
      @Unsigned int matchLength) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_updateTree($arg1, (const u8*)$arg2, (const u8*)$arg3)")
  public static void ZSTD_updateTree(Ptr<ZSTD_MatchState_t> ms,
      Ptr<java.lang. @OriginalName("BYTE") Character> ip,
      Ptr<java.lang. @OriginalName("BYTE") Character> iend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int ZSTD_versionNumber() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)ZSTD_versionString())")
  public static String ZSTD_versionString() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_writeFrameHeader($arg1, $arg2, (const ZSTD_CCtx_params_s*)$arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_writeFrameHeader(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<ZSTD_CCtx_params_s> params, @Unsigned long pledgedSrcSize, @Unsigned int dictID) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long ZSTD_writeLastEmptyBlock(Ptr<?> dst, @Unsigned long dstCapacity) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("ZSTD_writeSkippableFrame($arg1, $arg2, (const void*)$arg3, $arg4, $arg5)")
  public static @Unsigned long ZSTD_writeSkippableFrame(Ptr<?> dst, @Unsigned long dstCapacity,
      Ptr<?> src, @Unsigned long srcSize, @Unsigned int magicVariant) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_cctx_init($arg1, (const struct {\n"
          + "  struct {\n"
          + "    unsigned int windowLog;\n"
          + "    unsigned int chainLog;\n"
          + "    unsigned int hashLog;\n"
          + "    unsigned int searchLog;\n"
          + "    unsigned int minMatch;\n"
          + "    unsigned int targetLength;\n"
          + "    strategy_of_ZSTD_compressionParameters strategy;\n"
          + "  } cParams;\n"
          + "  struct {\n"
          + "    int contentSizeFlag;\n"
          + "    int checksumFlag;\n"
          + "    int noDictIDFlag;\n"
          + "  } fParams;\n"
          + "}*)$arg2, $arg3)")
  public static @Unsigned long zstd_cctx_init(Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> cctx,
      Ptr<@OriginalName("zstd_parameters") ZSTD_parameters> parameters,
      @Unsigned long pledged_src_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_cctx_set_param(Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> cctx,
      @OriginalName("ZSTD_cParameter") ZSTD_c param, int value) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_cctx_workspace_bound((const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg1)")
  public static @Unsigned long zstd_cctx_workspace_bound(
      Ptr<@OriginalName("zstd_compression_parameters") ZSTD_compressionParameters> cparams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_cctx_workspace_bound_with_ext_seq_prod((const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg1)")
  public static @Unsigned long zstd_cctx_workspace_bound_with_ext_seq_prod(
      Ptr<@OriginalName("zstd_compression_parameters") ZSTD_compressionParameters> compress_params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_compress_bound(@Unsigned long src_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_compress_cctx($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const struct {\n"
          + "  struct {\n"
          + "    unsigned int windowLog;\n"
          + "    unsigned int chainLog;\n"
          + "    unsigned int hashLog;\n"
          + "    unsigned int searchLog;\n"
          + "    unsigned int minMatch;\n"
          + "    unsigned int targetLength;\n"
          + "    strategy_of_ZSTD_compressionParameters strategy;\n"
          + "  } cParams;\n"
          + "  struct {\n"
          + "    int contentSizeFlag;\n"
          + "    int checksumFlag;\n"
          + "    int noDictIDFlag;\n"
          + "  } fParams;\n"
          + "}*)$arg6)")
  public static @Unsigned long zstd_compress_cctx(Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> cctx,
      Ptr<?> dst, @Unsigned long dst_capacity, Ptr<?> src, @Unsigned long src_size,
      Ptr<@OriginalName("zstd_parameters") ZSTD_parameters> parameters) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_compress_sequences_and_literals($arg1, $arg2, $arg3, (const struct {\n"
          + "  unsigned int offset;\n"
          + "  unsigned int litLength;\n"
          + "  unsigned int matchLength;\n"
          + "  unsigned int rep;\n"
          + "}*)$arg4, $arg5, (const void*)$arg6, $arg7, $arg8, $arg9)")
  public static @Unsigned long zstd_compress_sequences_and_literals(
      Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> cctx, Ptr<?> dst, @Unsigned long dst_capacity,
      Ptr<@OriginalName("zstd_sequence") ZSTD_Sequence> in_seqs, @Unsigned long in_seqs_size,
      Ptr<?> literals, @Unsigned long lit_size, @Unsigned long lit_capacity,
      @Unsigned long decompressed_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_compress_stream(
      Ptr<@OriginalName("zstd_cstream") ZSTD_CCtx_s> cstream,
      Ptr<@OriginalName("zstd_out_buffer") ZSTD_outBuffer_s> output,
      Ptr<@OriginalName("zstd_in_buffer") ZSTD_inBuffer_s> input) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_compress_using_cdict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const ZSTD_CDict_s*)$arg6)")
  public static @Unsigned long zstd_compress_using_cdict(
      Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> cctx, Ptr<?> dst, @Unsigned long dst_capacity,
      Ptr<?> src, @Unsigned long src_size, Ptr<ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> zstd_create_cctx_advanced(
      @OriginalName("zstd_custom_mem") ZSTD_customMem custom_mem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_create_cdict_byreference((const void*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<@OriginalName("zstd_cdict") ZSTD_CDict_s> zstd_create_cdict_byreference(
      Ptr<?> dict, @Unsigned long dict_size,
      @OriginalName("zstd_compression_parameters") ZSTD_compressionParameters cparams,
      @OriginalName("zstd_custom_mem") ZSTD_customMem custom_mem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("zstd_dctx") ZSTD_DCtx_s> zstd_create_dctx_advanced(
      @OriginalName("zstd_custom_mem") ZSTD_customMem custom_mem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_create_ddict_byreference((const void*)$arg1, $arg2, $arg3)")
  public static Ptr<@OriginalName("zstd_ddict") ZSTD_DDict_s> zstd_create_ddict_byreference(
      Ptr<?> dict, @Unsigned long dict_size,
      @OriginalName("zstd_custom_mem") ZSTD_customMem custom_mem) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_cstream_workspace_bound((const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg1)")
  public static @Unsigned long zstd_cstream_workspace_bound(
      Ptr<@OriginalName("zstd_compression_parameters") ZSTD_compressionParameters> cparams) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_cstream_workspace_bound_with_ext_seq_prod((const struct {\n"
          + "  unsigned int windowLog;\n"
          + "  unsigned int chainLog;\n"
          + "  unsigned int hashLog;\n"
          + "  unsigned int searchLog;\n"
          + "  unsigned int minMatch;\n"
          + "  unsigned int targetLength;\n"
          + "  strategy_of_ZSTD_compressionParameters strategy;\n"
          + "}*)$arg1)")
  public static @Unsigned long zstd_cstream_workspace_bound_with_ext_seq_prod(
      Ptr<@OriginalName("zstd_compression_parameters") ZSTD_compressionParameters> compress_params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_dctx_workspace_bound() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_decompress_dctx($arg1, $arg2, $arg3, (const void*)$arg4, $arg5)")
  public static @Unsigned long zstd_decompress_dctx(
      Ptr<@OriginalName("zstd_dctx") ZSTD_DCtx_s> dctx, Ptr<?> dst, @Unsigned long dst_capacity,
      Ptr<?> src, @Unsigned long src_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_decompress_stream(
      Ptr<@OriginalName("zstd_dstream") ZSTD_DCtx_s> dstream,
      Ptr<@OriginalName("zstd_out_buffer") ZSTD_outBuffer_s> output,
      Ptr<@OriginalName("zstd_in_buffer") ZSTD_inBuffer_s> input) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_decompress_using_ddict($arg1, $arg2, $arg3, (const void*)$arg4, $arg5, (const ZSTD_DDict_s*)$arg6)")
  public static @Unsigned long zstd_decompress_using_ddict(
      Ptr<@OriginalName("zstd_dctx") ZSTD_DCtx_s> dctx, Ptr<?> dst, @Unsigned long dst_capacity,
      Ptr<?> src, @Unsigned long src_size, Ptr<@OriginalName("zstd_ddict") ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int zstd_default_clevel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_dstream_workspace_bound(@Unsigned long max_window_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_end_stream(
      Ptr<@OriginalName("zstd_cstream") ZSTD_CCtx_s> cstream,
      Ptr<@OriginalName("zstd_out_buffer") ZSTD_outBuffer_s> output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_find_frame_compressed_size((const void*)$arg1, $arg2)")
  public static @Unsigned long zstd_find_frame_compressed_size(Ptr<?> src,
      @Unsigned long src_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_flush_stream(
      Ptr<@OriginalName("zstd_cstream") ZSTD_CCtx_s> cstream,
      Ptr<@OriginalName("zstd_out_buffer") ZSTD_outBuffer_s> output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void zstd_free(Ptr<?> strm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_free_cctx(Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> cctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_free_cdict(
      Ptr<@OriginalName("zstd_cdict") ZSTD_CDict_s> cdict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_free_dctx(Ptr<@OriginalName("zstd_dctx") ZSTD_DCtx_s> dctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_free_ddict(
      Ptr<@OriginalName("zstd_ddict") ZSTD_DDict_s> ddict) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("zstd_error_code") ZSTD_error zstd_get_error_code(
      @Unsigned long code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)zstd_get_error_name($arg1))")
  public static String zstd_get_error_name(@Unsigned long code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_get_frame_header($arg1, (const void*)$arg2, $arg3)")
  public static @Unsigned long zstd_get_frame_header(
      Ptr<@OriginalName("zstd_frame_header") ZSTD_FrameHeader> header, Ptr<?> src,
      @Unsigned long src_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<?> zstd_init(Ptr<squashfs_sb_info> msblk, Ptr<?> buff) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> zstd_init_cctx(Ptr<?> workspace,
      @Unsigned long workspace_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("zstd_init_cstream((const struct {\n"
          + "  struct {\n"
          + "    unsigned int windowLog;\n"
          + "    unsigned int chainLog;\n"
          + "    unsigned int hashLog;\n"
          + "    unsigned int searchLog;\n"
          + "    unsigned int minMatch;\n"
          + "    unsigned int targetLength;\n"
          + "    strategy_of_ZSTD_compressionParameters strategy;\n"
          + "  } cParams;\n"
          + "  struct {\n"
          + "    int contentSizeFlag;\n"
          + "    int checksumFlag;\n"
          + "    int noDictIDFlag;\n"
          + "  } fParams;\n"
          + "}*)$arg1, $arg2, $arg3, $arg4)")
  public static Ptr<@OriginalName("zstd_cstream") ZSTD_CCtx_s> zstd_init_cstream(
      Ptr<@OriginalName("zstd_parameters") ZSTD_parameters> parameters,
      @Unsigned long pledged_src_size, Ptr<?> workspace, @Unsigned long workspace_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("zstd_dctx") ZSTD_DCtx_s> zstd_init_dctx(Ptr<?> workspace,
      @Unsigned long workspace_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<@OriginalName("zstd_dstream") ZSTD_DCtx_s> zstd_init_dstream(
      @Unsigned long max_window_size, Ptr<?> workspace, @Unsigned long workspace_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int zstd_is_error(@Unsigned long code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int zstd_max_clevel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int zstd_min_clevel() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void zstd_register_sequence_producer(
      Ptr<@OriginalName("zstd_cctx") ZSTD_CCtx_s> cctx, Ptr<?> sequence_producer_state,
      @OriginalName("zstd_sequence_producer_f") Ptr<?> sequence_producer) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_reset_cstream(
      Ptr<@OriginalName("zstd_cstream") ZSTD_CCtx_s> cstream, @Unsigned long pledged_src_size) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long zstd_reset_dstream(
      Ptr<@OriginalName("zstd_dstream") ZSTD_DCtx_s> dstream) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int zstd_uncompress(Ptr<squashfs_sb_info> msblk, Ptr<?> strm, Ptr<bio> bio,
      int offset, int length, Ptr<squashfs_page_actor> output) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_error"
  )
  public enum ZSTD_error implements Enum<ZSTD_error>, TypedEnum<ZSTD_error, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_error_no_error = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_error_no_error"
    )
    ZSTD_error_no_error,

    /**
     * {@code ZSTD_error_GENERIC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_error_GENERIC"
    )
    ZSTD_error_GENERIC,

    /**
     * {@code ZSTD_error_prefix_unknown = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ZSTD_error_prefix_unknown"
    )
    ZSTD_error_prefix_unknown,

    /**
     * {@code ZSTD_error_version_unsupported = 12}
     */
    @EnumMember(
        value = 12L,
        name = "ZSTD_error_version_unsupported"
    )
    ZSTD_error_version_unsupported,

    /**
     * {@code ZSTD_error_frameParameter_unsupported = 14}
     */
    @EnumMember(
        value = 14L,
        name = "ZSTD_error_frameParameter_unsupported"
    )
    ZSTD_error_frameParameter_unsupported,

    /**
     * {@code ZSTD_error_frameParameter_windowTooLarge = 16}
     */
    @EnumMember(
        value = 16L,
        name = "ZSTD_error_frameParameter_windowTooLarge"
    )
    ZSTD_error_frameParameter_windowTooLarge,

    /**
     * {@code ZSTD_error_corruption_detected = 20}
     */
    @EnumMember(
        value = 20L,
        name = "ZSTD_error_corruption_detected"
    )
    ZSTD_error_corruption_detected,

    /**
     * {@code ZSTD_error_checksum_wrong = 22}
     */
    @EnumMember(
        value = 22L,
        name = "ZSTD_error_checksum_wrong"
    )
    ZSTD_error_checksum_wrong,

    /**
     * {@code ZSTD_error_literals_headerWrong = 24}
     */
    @EnumMember(
        value = 24L,
        name = "ZSTD_error_literals_headerWrong"
    )
    ZSTD_error_literals_headerWrong,

    /**
     * {@code ZSTD_error_dictionary_corrupted = 30}
     */
    @EnumMember(
        value = 30L,
        name = "ZSTD_error_dictionary_corrupted"
    )
    ZSTD_error_dictionary_corrupted,

    /**
     * {@code ZSTD_error_dictionary_wrong = 32}
     */
    @EnumMember(
        value = 32L,
        name = "ZSTD_error_dictionary_wrong"
    )
    ZSTD_error_dictionary_wrong,

    /**
     * {@code ZSTD_error_dictionaryCreation_failed = 34}
     */
    @EnumMember(
        value = 34L,
        name = "ZSTD_error_dictionaryCreation_failed"
    )
    ZSTD_error_dictionaryCreation_failed,

    /**
     * {@code ZSTD_error_parameter_unsupported = 40}
     */
    @EnumMember(
        value = 40L,
        name = "ZSTD_error_parameter_unsupported"
    )
    ZSTD_error_parameter_unsupported,

    /**
     * {@code ZSTD_error_parameter_combination_unsupported = 41}
     */
    @EnumMember(
        value = 41L,
        name = "ZSTD_error_parameter_combination_unsupported"
    )
    ZSTD_error_parameter_combination_unsupported,

    /**
     * {@code ZSTD_error_parameter_outOfBound = 42}
     */
    @EnumMember(
        value = 42L,
        name = "ZSTD_error_parameter_outOfBound"
    )
    ZSTD_error_parameter_outOfBound,

    /**
     * {@code ZSTD_error_tableLog_tooLarge = 44}
     */
    @EnumMember(
        value = 44L,
        name = "ZSTD_error_tableLog_tooLarge"
    )
    ZSTD_error_tableLog_tooLarge,

    /**
     * {@code ZSTD_error_maxSymbolValue_tooLarge = 46}
     */
    @EnumMember(
        value = 46L,
        name = "ZSTD_error_maxSymbolValue_tooLarge"
    )
    ZSTD_error_maxSymbolValue_tooLarge,

    /**
     * {@code ZSTD_error_maxSymbolValue_tooSmall = 48}
     */
    @EnumMember(
        value = 48L,
        name = "ZSTD_error_maxSymbolValue_tooSmall"
    )
    ZSTD_error_maxSymbolValue_tooSmall,

    /**
     * {@code ZSTD_error_cannotProduce_uncompressedBlock = 49}
     */
    @EnumMember(
        value = 49L,
        name = "ZSTD_error_cannotProduce_uncompressedBlock"
    )
    ZSTD_error_cannotProduce_uncompressedBlock,

    /**
     * {@code ZSTD_error_stabilityCondition_notRespected = 50}
     */
    @EnumMember(
        value = 50L,
        name = "ZSTD_error_stabilityCondition_notRespected"
    )
    ZSTD_error_stabilityCondition_notRespected,

    /**
     * {@code ZSTD_error_stage_wrong = 60}
     */
    @EnumMember(
        value = 60L,
        name = "ZSTD_error_stage_wrong"
    )
    ZSTD_error_stage_wrong,

    /**
     * {@code ZSTD_error_init_missing = 62}
     */
    @EnumMember(
        value = 62L,
        name = "ZSTD_error_init_missing"
    )
    ZSTD_error_init_missing,

    /**
     * {@code ZSTD_error_memory_allocation = 64}
     */
    @EnumMember(
        value = 64L,
        name = "ZSTD_error_memory_allocation"
    )
    ZSTD_error_memory_allocation,

    /**
     * {@code ZSTD_error_workSpace_tooSmall = 66}
     */
    @EnumMember(
        value = 66L,
        name = "ZSTD_error_workSpace_tooSmall"
    )
    ZSTD_error_workSpace_tooSmall,

    /**
     * {@code ZSTD_error_dstSize_tooSmall = 70}
     */
    @EnumMember(
        value = 70L,
        name = "ZSTD_error_dstSize_tooSmall"
    )
    ZSTD_error_dstSize_tooSmall,

    /**
     * {@code ZSTD_error_srcSize_wrong = 72}
     */
    @EnumMember(
        value = 72L,
        name = "ZSTD_error_srcSize_wrong"
    )
    ZSTD_error_srcSize_wrong,

    /**
     * {@code ZSTD_error_dstBuffer_null = 74}
     */
    @EnumMember(
        value = 74L,
        name = "ZSTD_error_dstBuffer_null"
    )
    ZSTD_error_dstBuffer_null,

    /**
     * {@code ZSTD_error_noForwardProgress_destFull = 80}
     */
    @EnumMember(
        value = 80L,
        name = "ZSTD_error_noForwardProgress_destFull"
    )
    ZSTD_error_noForwardProgress_destFull,

    /**
     * {@code ZSTD_error_noForwardProgress_inputEmpty = 82}
     */
    @EnumMember(
        value = 82L,
        name = "ZSTD_error_noForwardProgress_inputEmpty"
    )
    ZSTD_error_noForwardProgress_inputEmpty,

    /**
     * {@code ZSTD_error_frameIndex_tooLarge = 100}
     */
    @EnumMember(
        value = 100L,
        name = "ZSTD_error_frameIndex_tooLarge"
    )
    ZSTD_error_frameIndex_tooLarge,

    /**
     * {@code ZSTD_error_seekableIO = 102}
     */
    @EnumMember(
        value = 102L,
        name = "ZSTD_error_seekableIO"
    )
    ZSTD_error_seekableIO,

    /**
     * {@code ZSTD_error_dstBuffer_wrong = 104}
     */
    @EnumMember(
        value = 104L,
        name = "ZSTD_error_dstBuffer_wrong"
    )
    ZSTD_error_dstBuffer_wrong,

    /**
     * {@code ZSTD_error_srcBuffer_wrong = 105}
     */
    @EnumMember(
        value = 105L,
        name = "ZSTD_error_srcBuffer_wrong"
    )
    ZSTD_error_srcBuffer_wrong,

    /**
     * {@code ZSTD_error_sequenceProducer_failed = 106}
     */
    @EnumMember(
        value = 106L,
        name = "ZSTD_error_sequenceProducer_failed"
    )
    ZSTD_error_sequenceProducer_failed,

    /**
     * {@code ZSTD_error_externalSequences_invalid = 107}
     */
    @EnumMember(
        value = 107L,
        name = "ZSTD_error_externalSequences_invalid"
    )
    ZSTD_error_externalSequences_invalid,

    /**
     * {@code ZSTD_error_maxCode = 120}
     */
    @EnumMember(
        value = 120L,
        name = "ZSTD_error_maxCode"
    )
    ZSTD_error_maxCode
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ZSTD_inBuffer_s"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_inBuffer_s extends Struct {
    public Ptr<?> src;

    public @Unsigned long size;

    public @Unsigned long pos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ZSTD_outBuffer_s"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_outBuffer_s extends Struct {
    public Ptr<?> dst;

    public @Unsigned long size;

    public @Unsigned long pos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void* (*customAlloc)(void*, long unsigned int); void (*customFree)(void*, void*); void *opaque; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_customMem extends Struct {
    public @OriginalName("ZSTD_allocFunction") Ptr<?> customAlloc;

    public @OriginalName("ZSTD_freeFunction") Ptr<?> customFree;

    public Ptr<?> opaque;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int windowLog; unsigned int chainLog; unsigned int hashLog; unsigned int searchLog; unsigned int minMatch; unsigned int targetLength; strategy_of_ZSTD_compressionParameters strategy; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_compressionParameters extends Struct {
    public @Unsigned int windowLog;

    public @Unsigned int chainLog;

    public @Unsigned int hashLog;

    public @Unsigned int searchLog;

    public @Unsigned int minMatch;

    public @Unsigned int targetLength;

    public @OriginalName("ZSTD_strategy") strategy_of_ZSTD_compressionParameters strategy;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int contentSizeFlag; int checksumFlag; int noDictIDFlag; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_frameParameters extends Struct {
    public int contentSizeFlag;

    public int checksumFlag;

    public int noDictIDFlag;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { unsigned int windowLog; unsigned int chainLog; unsigned int hashLog; unsigned int searchLog; unsigned int minMatch; unsigned int targetLength; strategy_of_ZSTD_compressionParameters strategy; } cParams; struct { int contentSizeFlag; int checksumFlag; int noDictIDFlag; } fParams; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_parameters extends Struct {
    public ZSTD_compressionParameters cParams;

    public ZSTD_frameParameters fParams;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_c"
  )
  public enum ZSTD_c implements Enum<ZSTD_c>, TypedEnum<ZSTD_c, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_c_compressionLevel = 100}
     */
    @EnumMember(
        value = 100L,
        name = "ZSTD_c_compressionLevel"
    )
    ZSTD_c_compressionLevel,

    /**
     * {@code ZSTD_c_windowLog = 101}
     */
    @EnumMember(
        value = 101L,
        name = "ZSTD_c_windowLog"
    )
    ZSTD_c_windowLog,

    /**
     * {@code ZSTD_c_hashLog = 102}
     */
    @EnumMember(
        value = 102L,
        name = "ZSTD_c_hashLog"
    )
    ZSTD_c_hashLog,

    /**
     * {@code ZSTD_c_chainLog = 103}
     */
    @EnumMember(
        value = 103L,
        name = "ZSTD_c_chainLog"
    )
    ZSTD_c_chainLog,

    /**
     * {@code ZSTD_c_searchLog = 104}
     */
    @EnumMember(
        value = 104L,
        name = "ZSTD_c_searchLog"
    )
    ZSTD_c_searchLog,

    /**
     * {@code ZSTD_c_minMatch = 105}
     */
    @EnumMember(
        value = 105L,
        name = "ZSTD_c_minMatch"
    )
    ZSTD_c_minMatch,

    /**
     * {@code ZSTD_c_targetLength = 106}
     */
    @EnumMember(
        value = 106L,
        name = "ZSTD_c_targetLength"
    )
    ZSTD_c_targetLength,

    /**
     * {@code ZSTD_c_strategy = 107}
     */
    @EnumMember(
        value = 107L,
        name = "ZSTD_c_strategy"
    )
    ZSTD_c_strategy,

    /**
     * {@code ZSTD_c_targetCBlockSize = 130}
     */
    @EnumMember(
        value = 130L,
        name = "ZSTD_c_targetCBlockSize"
    )
    ZSTD_c_targetCBlockSize,

    /**
     * {@code ZSTD_c_enableLongDistanceMatching = 160}
     */
    @EnumMember(
        value = 160L,
        name = "ZSTD_c_enableLongDistanceMatching"
    )
    ZSTD_c_enableLongDistanceMatching,

    /**
     * {@code ZSTD_c_ldmHashLog = 161}
     */
    @EnumMember(
        value = 161L,
        name = "ZSTD_c_ldmHashLog"
    )
    ZSTD_c_ldmHashLog,

    /**
     * {@code ZSTD_c_ldmMinMatch = 162}
     */
    @EnumMember(
        value = 162L,
        name = "ZSTD_c_ldmMinMatch"
    )
    ZSTD_c_ldmMinMatch,

    /**
     * {@code ZSTD_c_ldmBucketSizeLog = 163}
     */
    @EnumMember(
        value = 163L,
        name = "ZSTD_c_ldmBucketSizeLog"
    )
    ZSTD_c_ldmBucketSizeLog,

    /**
     * {@code ZSTD_c_ldmHashRateLog = 164}
     */
    @EnumMember(
        value = 164L,
        name = "ZSTD_c_ldmHashRateLog"
    )
    ZSTD_c_ldmHashRateLog,

    /**
     * {@code ZSTD_c_contentSizeFlag = 200}
     */
    @EnumMember(
        value = 200L,
        name = "ZSTD_c_contentSizeFlag"
    )
    ZSTD_c_contentSizeFlag,

    /**
     * {@code ZSTD_c_checksumFlag = 201}
     */
    @EnumMember(
        value = 201L,
        name = "ZSTD_c_checksumFlag"
    )
    ZSTD_c_checksumFlag,

    /**
     * {@code ZSTD_c_dictIDFlag = 202}
     */
    @EnumMember(
        value = 202L,
        name = "ZSTD_c_dictIDFlag"
    )
    ZSTD_c_dictIDFlag,

    /**
     * {@code ZSTD_c_nbWorkers = 400}
     */
    @EnumMember(
        value = 400L,
        name = "ZSTD_c_nbWorkers"
    )
    ZSTD_c_nbWorkers,

    /**
     * {@code ZSTD_c_jobSize = 401}
     */
    @EnumMember(
        value = 401L,
        name = "ZSTD_c_jobSize"
    )
    ZSTD_c_jobSize,

    /**
     * {@code ZSTD_c_overlapLog = 402}
     */
    @EnumMember(
        value = 402L,
        name = "ZSTD_c_overlapLog"
    )
    ZSTD_c_overlapLog,

    /**
     * {@code ZSTD_c_experimentalParam1 = 500}
     */
    @EnumMember(
        value = 500L,
        name = "ZSTD_c_experimentalParam1"
    )
    ZSTD_c_experimentalParam1,

    /**
     * {@code ZSTD_c_experimentalParam2 = 10}
     */
    @EnumMember(
        value = 10L,
        name = "ZSTD_c_experimentalParam2"
    )
    ZSTD_c_experimentalParam2,

    /**
     * {@code ZSTD_c_experimentalParam3 = 1000}
     */
    @EnumMember(
        value = 1000L,
        name = "ZSTD_c_experimentalParam3"
    )
    ZSTD_c_experimentalParam3,

    /**
     * {@code ZSTD_c_experimentalParam4 = 1001}
     */
    @EnumMember(
        value = 1001L,
        name = "ZSTD_c_experimentalParam4"
    )
    ZSTD_c_experimentalParam4,

    /**
     * {@code ZSTD_c_experimentalParam5 = 1002}
     */
    @EnumMember(
        value = 1002L,
        name = "ZSTD_c_experimentalParam5"
    )
    ZSTD_c_experimentalParam5,

    /**
     * {@code ZSTD_c_experimentalParam7 = 1004}
     */
    @EnumMember(
        value = 1004L,
        name = "ZSTD_c_experimentalParam7"
    )
    ZSTD_c_experimentalParam7,

    /**
     * {@code ZSTD_c_experimentalParam8 = 1005}
     */
    @EnumMember(
        value = 1005L,
        name = "ZSTD_c_experimentalParam8"
    )
    ZSTD_c_experimentalParam8,

    /**
     * {@code ZSTD_c_experimentalParam9 = 1006}
     */
    @EnumMember(
        value = 1006L,
        name = "ZSTD_c_experimentalParam9"
    )
    ZSTD_c_experimentalParam9,

    /**
     * {@code ZSTD_c_experimentalParam10 = 1007}
     */
    @EnumMember(
        value = 1007L,
        name = "ZSTD_c_experimentalParam10"
    )
    ZSTD_c_experimentalParam10,

    /**
     * {@code ZSTD_c_experimentalParam11 = 1008}
     */
    @EnumMember(
        value = 1008L,
        name = "ZSTD_c_experimentalParam11"
    )
    ZSTD_c_experimentalParam11,

    /**
     * {@code ZSTD_c_experimentalParam12 = 1009}
     */
    @EnumMember(
        value = 1009L,
        name = "ZSTD_c_experimentalParam12"
    )
    ZSTD_c_experimentalParam12,

    /**
     * {@code ZSTD_c_experimentalParam13 = 1010}
     */
    @EnumMember(
        value = 1010L,
        name = "ZSTD_c_experimentalParam13"
    )
    ZSTD_c_experimentalParam13,

    /**
     * {@code ZSTD_c_experimentalParam14 = 1011}
     */
    @EnumMember(
        value = 1011L,
        name = "ZSTD_c_experimentalParam14"
    )
    ZSTD_c_experimentalParam14,

    /**
     * {@code ZSTD_c_experimentalParam15 = 1012}
     */
    @EnumMember(
        value = 1012L,
        name = "ZSTD_c_experimentalParam15"
    )
    ZSTD_c_experimentalParam15,

    /**
     * {@code ZSTD_c_experimentalParam16 = 1013}
     */
    @EnumMember(
        value = 1013L,
        name = "ZSTD_c_experimentalParam16"
    )
    ZSTD_c_experimentalParam16,

    /**
     * {@code ZSTD_c_experimentalParam17 = 1014}
     */
    @EnumMember(
        value = 1014L,
        name = "ZSTD_c_experimentalParam17"
    )
    ZSTD_c_experimentalParam17,

    /**
     * {@code ZSTD_c_experimentalParam18 = 1015}
     */
    @EnumMember(
        value = 1015L,
        name = "ZSTD_c_experimentalParam18"
    )
    ZSTD_c_experimentalParam18,

    /**
     * {@code ZSTD_c_experimentalParam19 = 1016}
     */
    @EnumMember(
        value = 1016L,
        name = "ZSTD_c_experimentalParam19"
    )
    ZSTD_c_experimentalParam19,

    /**
     * {@code ZSTD_c_experimentalParam20 = 1017}
     */
    @EnumMember(
        value = 1017L,
        name = "ZSTD_c_experimentalParam20"
    )
    ZSTD_c_experimentalParam20
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_reset"
  )
  public enum ZSTD_reset implements Enum<ZSTD_reset>, TypedEnum<ZSTD_reset, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_reset_session_only = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_reset_session_only"
    )
    ZSTD_reset_session_only,

    /**
     * {@code ZSTD_reset_parameters = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ZSTD_reset_parameters"
    )
    ZSTD_reset_parameters,

    /**
     * {@code ZSTD_reset_session_and_parameters = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ZSTD_reset_session_and_parameters"
    )
    ZSTD_reset_session_and_parameters
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_dlm_by"
  )
  public enum ZSTD_dlm_by implements Enum<ZSTD_dlm_by>, TypedEnum<ZSTD_dlm_by, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_dlm_byCopy = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_dlm_byCopy"
    )
    ZSTD_dlm_byCopy,

    /**
     * {@code ZSTD_dlm_byRef = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_dlm_byRef"
    )
    ZSTD_dlm_byRef
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void *workspace; void *workspaceEnd; void *objectEnd; void *tableEnd; void *tableValidEnd; void *allocStart; void *initOnceStart; u8 allocFailed; int workspaceOversizedDuration; phase_of_ZSTD_cwksp phase; isStatic_of_ZSTD_cwksp isStatic; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_cwksp extends Struct {
    public Ptr<?> workspace;

    public Ptr<?> workspaceEnd;

    public Ptr<?> objectEnd;

    public Ptr<?> tableEnd;

    public Ptr<?> tableValidEnd;

    public Ptr<?> allocStart;

    public Ptr<?> initOnceStart;

    public @OriginalName("BYTE") char allocFailed;

    public int workspaceOversizedDuration;

    public @OriginalName("ZSTD_cwksp_alloc_phase_e") phase_of_ZSTD_cwksp phase;

    public @OriginalName("ZSTD_cwksp_static_alloc_e") isStatic_of_ZSTD_cwksp isStatic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct ZSTD_prefixDict_s"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_prefixDict_s extends Struct {
    public Ptr<?> dict;

    public @Unsigned long dictSize;

    public @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { void *dictBuffer; const void*; long unsigned int dictSize; dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType; ZSTD_CDict_s *cdict; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_localDict extends Struct {
    public Ptr<?> dictBuffer;

    public Ptr<?> dict;

    public @Unsigned long dictSize;

    public @OriginalName("ZSTD_dictContentType_e") dictContentType_of_ZSTD_CDict_and_dictContentType_of_ZSTD_CDict_s_and_dictContentType_of_ZSTD_localDict dictContentType;

    public Ptr<ZSTD_CDict_s> cdict;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int CTable[257]; repeatMode_of_ZSTD_hufCTables_t repeatMode; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_hufCTables_t extends Struct {
    public @Unsigned @OriginalName("HUF_CElt") long @Size(257) [] CTable;

    public @OriginalName("HUF_repeat") repeatMode_of_ZSTD_hufCTables_t repeatMode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int offcodeCTable[193]; unsigned int matchlengthCTable[363]; unsigned int litlengthCTable[329]; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_fseCTables_t extends Struct {
    public @Unsigned @OriginalName("FSE_CTable") int @Size(193) [] offcodeCTable;

    public @Unsigned @OriginalName("FSE_CTable") int @Size(363) [] matchlengthCTable;

    public @Unsigned @OriginalName("FSE_CTable") int @Size(329) [] litlengthCTable;

    public @OriginalName("FSE_repeat") litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode;

    public @OriginalName("FSE_repeat") litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode;

    public @OriginalName("FSE_repeat") litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { long unsigned int CTable[257]; repeatMode_of_ZSTD_hufCTables_t repeatMode; } huf; struct { unsigned int offcodeCTable[193]; unsigned int matchlengthCTable[363]; unsigned int litlengthCTable[329]; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode; } fse; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_entropyCTables_t extends Struct {
    public ZSTD_hufCTables_t huf;

    public ZSTD_fseCTables_t fse;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t hType; u8 hufDesBuffer[128]; long unsigned int hufDesSize; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_hufCTablesMetadata_t extends Struct {
    public @OriginalName("SymbolEncodingType_e") hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t hType;

    public @OriginalName("BYTE") char @Size(128) [] hufDesBuffer;

    public @Unsigned long hufDesSize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t llType; hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t ofType; hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t mlType; u8 fseTablesBuffer[133]; long unsigned int fseTablesSize; long unsigned int lastCountSize; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_fseCTablesMetadata_t extends Struct {
    public @OriginalName("SymbolEncodingType_e") hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t llType;

    public @OriginalName("SymbolEncodingType_e") hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t ofType;

    public @OriginalName("SymbolEncodingType_e") hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t mlType;

    public @OriginalName("BYTE") char @Size(133) [] fseTablesBuffer;

    public @Unsigned long fseTablesSize;

    public @Unsigned long lastCountSize;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t hType; u8 hufDesBuffer[128]; long unsigned int hufDesSize; } hufMetadata; struct { hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t llType; hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t ofType; hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t mlType; u8 fseTablesBuffer[133]; long unsigned int fseTablesSize; long unsigned int lastCountSize; } fseMetadata; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_entropyCTablesMetadata_t extends Struct {
    public ZSTD_hufCTablesMetadata_t hufMetadata;

    public ZSTD_fseCTablesMetadata_t fseMetadata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int off; unsigned int len; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_match_t extends Struct {
    public @Unsigned int off;

    public @Unsigned int len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { int price; unsigned int off; unsigned int mlen; unsigned int litlen; unsigned int rep[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_optimal_t extends Struct {
    public int price;

    public @Unsigned int off;

    public @Unsigned int mlen;

    public @Unsigned int litlen;

    public @Unsigned int @Size(3) [] rep;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { struct { long unsigned int CTable[257]; repeatMode_of_ZSTD_hufCTables_t repeatMode; } huf; struct { unsigned int offcodeCTable[193]; unsigned int matchlengthCTable[363]; unsigned int litlengthCTable[329]; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode; } fse; } entropy; unsigned int rep[3]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_compressedBlockState_t extends Struct {
    public ZSTD_entropyCTables_t entropy;

    public @Unsigned int @Size(3) [] rep;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { const u8*; const u8*; const u8*; unsigned int dictLimit; unsigned int lowLimit; unsigned int nbOverflowCorrections; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_window_t extends Struct {
    public Ptr<java.lang. @OriginalName("BYTE") Character> nextSrc;

    public Ptr<java.lang. @OriginalName("BYTE") Character> base;

    public Ptr<java.lang. @OriginalName("BYTE") Character> dictBase;

    public @Unsigned int dictLimit;

    public @Unsigned int lowLimit;

    public @Unsigned int nbOverflowCorrections;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { struct { struct { long unsigned int CTable[257]; repeatMode_of_ZSTD_hufCTables_t repeatMode; } huf; struct { unsigned int offcodeCTable[193]; unsigned int matchlengthCTable[363]; unsigned int litlengthCTable[329]; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode; } fse; } entropy; unsigned int rep[3]; } *prevCBlock; struct { struct { struct { long unsigned int CTable[257]; repeatMode_of_ZSTD_hufCTables_t repeatMode; } huf; struct { unsigned int offcodeCTable[193]; unsigned int matchlengthCTable[363]; unsigned int litlengthCTable[329]; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t offcode_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t matchlength_repeatMode; litlength_repeatMode_of_ZSTD_fseCTables_t_and_matchlength_repeatMode_of_ZSTD_fseCTables_t_and_offcode_repeatMode_of_ZSTD_fseCTables_t litlength_repeatMode; } fse; } entropy; unsigned int rep[3]; } *nextCBlock; ZSTD_MatchState_t matchState; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_blockState_t extends Struct {
    public Ptr<ZSTD_compressedBlockState_t> prevCBlock;

    public Ptr<ZSTD_compressedBlockState_t> nextCBlock;

    public ZSTD_MatchState_t matchState;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { SeqDef_s *sequencesStart; SeqDef_s *sequences; u8 *litStart; u8 *lit; u8 *llCode; u8 *mlCode; u8 *ofCode; long unsigned int maxNbSeq; long unsigned int maxNbLit; longLengthType_of_SeqStore_t longLengthType; unsigned int longLengthPos; } fullSeqStoreChunk; struct { SeqDef_s *sequencesStart; SeqDef_s *sequences; u8 *litStart; u8 *lit; u8 *llCode; u8 *mlCode; u8 *ofCode; long unsigned int maxNbSeq; long unsigned int maxNbLit; longLengthType_of_SeqStore_t longLengthType; unsigned int longLengthPos; } firstHalfSeqStore; struct { SeqDef_s *sequencesStart; SeqDef_s *sequences; u8 *litStart; u8 *lit; u8 *llCode; u8 *mlCode; u8 *ofCode; long unsigned int maxNbSeq; long unsigned int maxNbLit; longLengthType_of_SeqStore_t longLengthType; unsigned int longLengthPos; } secondHalfSeqStore; struct { SeqDef_s *sequencesStart; SeqDef_s *sequences; u8 *litStart; u8 *lit; u8 *llCode; u8 *mlCode; u8 *ofCode; long unsigned int maxNbSeq; long unsigned int maxNbLit; longLengthType_of_SeqStore_t longLengthType; unsigned int longLengthPos; } currSeqStore; struct { SeqDef_s *sequencesStart; SeqDef_s *sequences; u8 *litStart; u8 *lit; u8 *llCode; u8 *mlCode; u8 *ofCode; long unsigned int maxNbSeq; long unsigned int maxNbLit; longLengthType_of_SeqStore_t longLengthType; unsigned int longLengthPos; } nextSeqStore; unsigned int partitions[196]; struct { struct { hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t hType; u8 hufDesBuffer[128]; long unsigned int hufDesSize; } hufMetadata; struct { hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t llType; hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t ofType; hType_of_ZSTD_hufCTablesMetadata_t_and_llType_of_ZSTD_fseCTablesMetadata_t_and_mlType_of_ZSTD_fseCTablesMetadata_t mlType; u8 fseTablesBuffer[133]; long unsigned int fseTablesSize; long unsigned int lastCountSize; } fseMetadata; } entropyMetadata; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_blockSplitCtx extends Struct {
    public SeqStore_t fullSeqStoreChunk;

    public SeqStore_t firstHalfSeqStore;

    public SeqStore_t secondHalfSeqStore;

    public SeqStore_t currSeqStore;

    public SeqStore_t nextSeqStore;

    public @Unsigned int @Size(196) [] partitions;

    public ZSTD_entropyCTablesMetadata_t entropyMetadata;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int error; int lowerBound; int upperBound; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_bounds extends Struct {
    public @Unsigned long error;

    public int lowerBound;

    public int upperBound;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_e"
  )
  public enum ZSTD_e implements Enum<ZSTD_e>, TypedEnum<ZSTD_e, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_e_continue = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_e_continue"
    )
    ZSTD_e_continue,

    /**
     * {@code ZSTD_e_flush = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_e_flush"
    )
    ZSTD_e_flush,

    /**
     * {@code ZSTD_e_end = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ZSTD_e_end"
    )
    ZSTD_e_end
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long long unsigned int ingested; long long unsigned int consumed; long long unsigned int produced; long long unsigned int flushed; unsigned int currentJobID; unsigned int nbActiveWorkers; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_frameProgression extends Struct {
    public @Unsigned long ingested;

    public @Unsigned long consumed;

    public @Unsigned long produced;

    public @Unsigned long flushed;

    public @Unsigned int currentJobID;

    public @Unsigned int nbActiveWorkers;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int f1c; unsigned int f1d; unsigned int f7b; unsigned int f7c; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_cpuid_t extends Struct {
    public @Unsigned int f1c;

    public @Unsigned int f1d;

    public @Unsigned int f7b;

    public @Unsigned int f7c;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_dtlm_f"
  )
  public enum ZSTD_dtlm_f implements Enum<ZSTD_dtlm_f>, TypedEnum<ZSTD_dtlm_f, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_dtlm_fast = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_dtlm_fast"
    )
    ZSTD_dtlm_fast,

    /**
     * {@code ZSTD_dtlm_full = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_dtlm_full"
    )
    ZSTD_dtlm_full
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_tfp_forC"
  )
  public enum ZSTD_tfp_forC implements Enum<ZSTD_tfp_forC>, TypedEnum<ZSTD_tfp_forC, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_tfp_forCCtx = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_tfp_forCCtx"
    )
    ZSTD_tfp_forCCtx,

    /**
     * {@code ZSTD_tfp_forCDict = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_tfp_forCDict"
    )
    ZSTD_tfp_forCDict
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_cpm"
  )
  public enum ZSTD_cpm implements Enum<ZSTD_cpm>, TypedEnum<ZSTD_cpm, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_cpm_noAttachDict = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_cpm_noAttachDict"
    )
    ZSTD_cpm_noAttachDict,

    /**
     * {@code ZSTD_cpm_attachDict = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_cpm_attachDict"
    )
    ZSTD_cpm_attachDict,

    /**
     * {@code ZSTD_cpm_createCDict = 2}
     */
    @EnumMember(
        value = 2L,
        name = "ZSTD_cpm_createCDict"
    )
    ZSTD_cpm_createCDict,

    /**
     * {@code ZSTD_cpm_unknown = 3}
     */
    @EnumMember(
        value = 3L,
        name = "ZSTD_cpm_unknown"
    )
    ZSTD_cpm_unknown
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_default"
  )
  public enum ZSTD_default implements Enum<ZSTD_default>, TypedEnum<ZSTD_default, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_defaultDisallowed = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_defaultDisallowed"
    )
    ZSTD_defaultDisallowed,

    /**
     * {@code ZSTD_defaultAllowed = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_defaultAllowed"
    )
    ZSTD_defaultAllowed
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_resetTarget_C"
  )
  public enum ZSTD_resetTarget_C implements Enum<ZSTD_resetTarget_C>, TypedEnum<ZSTD_resetTarget_C, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_resetTarget_CDict = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_resetTarget_CDict"
    )
    ZSTD_resetTarget_CDict,

    /**
     * {@code ZSTD_resetTarget_CCtx = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_resetTarget_CCtx"
    )
    ZSTD_resetTarget_CCtx
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int LLtype; unsigned int Offtype; unsigned int MLtype; long unsigned int size; long unsigned int lastCountSize; int longOffsets; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_symbolEncodingTypeStats_t extends Struct {
    public @Unsigned int LLtype;

    public @Unsigned int Offtype;

    public @Unsigned int MLtype;

    public @Unsigned long size;

    public @Unsigned long lastCountSize;

    public int longOffsets;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { struct { unsigned int offset; unsigned int litLength; unsigned int matchLength; } *seq; long unsigned int pos; long unsigned int posInSequence; long unsigned int size; long unsigned int capacity; } seqStore; unsigned int startPosInBlock; unsigned int endPosInBlock; unsigned int offset; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_optLdm_t extends Struct {
    public RawSeqStore_t seqStore;

    public @Unsigned int startPosInBlock;

    public @Unsigned int endPosInBlock;

    public @Unsigned int offset;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { short unsigned int nextState; u8 nbAdditionalBits; u8 nbBits; unsigned int baseValue; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_seqSymbol extends Struct {
    public @Unsigned short nextState;

    public @OriginalName("BYTE") char nbAdditionalBits;

    public @OriginalName("BYTE") char nbBits;

    public @Unsigned int baseValue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { struct { short unsigned int nextState; u8 nbAdditionalBits; u8 nbBits; unsigned int baseValue; } LLTable[513]; struct { short unsigned int nextState; u8 nbAdditionalBits; u8 nbBits; unsigned int baseValue; } OFTable[257]; struct { short unsigned int nextState; u8 nbAdditionalBits; u8 nbBits; unsigned int baseValue; } MLTable[513]; unsigned int hufTable[4097]; unsigned int rep[3]; unsigned int workspace[157]; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_entropyDTables_t extends Struct {
    public ZSTD_seqSymbol @Size(513) [] LLTable;

    public ZSTD_seqSymbol @Size(257) [] OFTable;

    public ZSTD_seqSymbol @Size(513) [] MLTable;

    public @Unsigned @OriginalName("HUF_DTable") int @Size(4097) [] hufTable;

    public @Unsigned int @Size(3) [] rep;

    public @Unsigned int @Size(157) [] workspace;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_d"
  )
  public enum ZSTD_d implements Enum<ZSTD_d>, TypedEnum<ZSTD_d, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_d_windowLogMax = 100}
     */
    @EnumMember(
        value = 100L,
        name = "ZSTD_d_windowLogMax"
    )
    ZSTD_d_windowLogMax,

    /**
     * {@code ZSTD_d_experimentalParam1 = 1000}
     */
    @EnumMember(
        value = 1000L,
        name = "ZSTD_d_experimentalParam1"
    )
    ZSTD_d_experimentalParam1,

    /**
     * {@code ZSTD_d_experimentalParam2 = 1001}
     */
    @EnumMember(
        value = 1001L,
        name = "ZSTD_d_experimentalParam2"
    )
    ZSTD_d_experimentalParam2,

    /**
     * {@code ZSTD_d_experimentalParam3 = 1002}
     */
    @EnumMember(
        value = 1002L,
        name = "ZSTD_d_experimentalParam3"
    )
    ZSTD_d_experimentalParam3,

    /**
     * {@code ZSTD_d_experimentalParam4 = 1003}
     */
    @EnumMember(
        value = 1003L,
        name = "ZSTD_d_experimentalParam4"
    )
    ZSTD_d_experimentalParam4,

    /**
     * {@code ZSTD_d_experimentalParam5 = 1004}
     */
    @EnumMember(
        value = 1004L,
        name = "ZSTD_d_experimentalParam5"
    )
    ZSTD_d_experimentalParam5,

    /**
     * {@code ZSTD_d_experimentalParam6 = 1005}
     */
    @EnumMember(
        value = 1005L,
        name = "ZSTD_d_experimentalParam6"
    )
    ZSTD_d_experimentalParam6
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int nbBlocks; long unsigned int compressedSize; long long unsigned int decompressedBound; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_frameSizeInfo extends Struct {
    public @Unsigned long nbBlocks;

    public @Unsigned long compressedSize;

    public @Unsigned long decompressedBound;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { unsigned int fastMode; unsigned int tableLog; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_seqSymbol_header extends Struct {
    public @Unsigned int fastMode;

    public @Unsigned int tableLog;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct { long unsigned int state; const struct { short unsigned int nextState; u8 nbAdditionalBits; u8 nbBits; unsigned int baseValue; }*; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class ZSTD_fseState extends Struct {
    public @Unsigned long state;

    public Ptr<ZSTD_seqSymbol> table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum ZSTD_lo_is"
  )
  public enum ZSTD_lo_is implements Enum<ZSTD_lo_is>, TypedEnum<ZSTD_lo_is, java.lang. @Unsigned Integer> {
    /**
     * {@code ZSTD_lo_isRegularOffset = 0}
     */
    @EnumMember(
        value = 0L,
        name = "ZSTD_lo_isRegularOffset"
    )
    ZSTD_lo_isRegularOffset,

    /**
     * {@code ZSTD_lo_isLongOffset = 1}
     */
    @EnumMember(
        value = 1L,
        name = "ZSTD_lo_isLongOffset"
    )
    ZSTD_lo_isLongOffset
  }
}
