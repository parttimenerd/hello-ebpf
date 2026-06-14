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
import static me.bechberger.ebpf.runtime.ZstdDefinitions.*;
import static me.bechberger.ebpf.runtime.ZswapDefinitions.*;
import static me.bechberger.ebpf.runtime.misc.*;
import static me.bechberger.ebpf.runtime.runtime.*;

/**
 * Generated class for BPF runtime types that start with xfrm
 */
@java.lang.SuppressWarnings("unused")
public final class XfrmDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __xfrm_decode_session(Ptr<net> net, Ptr<sk_buff> skb, Ptr<flowi> fl,
      @Unsigned int family, int reverse) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__xfrm_dst_hash((const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg1, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned int __xfrm_dst_hash(Ptr<xfrm_address_t> daddr, Ptr<xfrm_address_t> saddr,
      @Unsigned int reqid, @Unsigned short family, @Unsigned int hmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__xfrm_dst_lookup($arg1, (const struct xfrm_dst_lookup_params*)$arg2)")
  public static Ptr<dst_entry> __xfrm_dst_lookup(int family, Ptr<xfrm_dst_lookup_params> params) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __xfrm_init_state(Ptr<xfrm_state> x, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_mode_beet_prep(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned int hsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_mode_tunnel_prep(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned int hsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __xfrm_policy_check(Ptr<sock> sk, int dir, Ptr<sk_buff> skb,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_policy_inexact_prune_bin(Ptr<xfrm_pol_inexact_bin> b,
      boolean net_exit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_policy_link(Ptr<xfrm_policy> pol, int dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_policy> __xfrm_policy_unlink(Ptr<xfrm_policy> pol, int dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __xfrm_route_forward(Ptr<sk_buff> skb, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__xfrm_sk_clone_policy($arg1, (const struct sock*)$arg2)")
  public static int __xfrm_sk_clone_policy(Ptr<sock> sk, Ptr<sock> osk) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__xfrm_spi_hash((const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg1, $arg2, $arg3, $arg4, $arg5)")
  public static @Unsigned int __xfrm_spi_hash(Ptr<xfrm_address_t> daddr,
      @Unsigned @OriginalName("__be32") int spi, char proto, @Unsigned short family,
      @Unsigned int hmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("__xfrm_src_hash((const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg1, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg2, $arg3, $arg4)")
  public static @Unsigned int __xfrm_src_hash(Ptr<xfrm_address_t> daddr, Ptr<xfrm_address_t> saddr,
      @Unsigned short family, @Unsigned int hmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_state_bump_genids(Ptr<xfrm_state> xnew) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int __xfrm_state_delete(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_state_destroy(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_state_insert(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void __xfrm_transport_prep(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned int hsize) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_alloc_spi(Ptr<xfrm_state> x, @Unsigned int low, @Unsigned int high,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_api_check(Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_common_policyinfo(Ptr<xfrm_policy> xp,
      Ptr<audit_buffer> audit_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_helper_pktinfo(Ptr<sk_buff> skb, @Unsigned short family,
      Ptr<audit_buffer> audit_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_helper_sainfo(Ptr<xfrm_state> x, Ptr<audit_buffer> audit_buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_policy_add(Ptr<xfrm_policy> xp, int result, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_policy_delete(Ptr<xfrm_policy> xp, int result, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_state_add(Ptr<xfrm_state> x, int result, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_state_delete(Ptr<xfrm_state> x, int result, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_state_icvfail(Ptr<xfrm_state> x, Ptr<sk_buff> skb, char proto) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_state_notfound(Ptr<sk_buff> skb, @Unsigned short family,
      @Unsigned @OriginalName("__be32") int net_spi,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_state_notfound_simple(Ptr<sk_buff> skb, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_state_replay(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_audit_state_replay_overflow(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_bundle_create($arg1, $arg2, $arg3, $arg4, (const struct flowi*)$arg5, $arg6)")
  public static Ptr<dst_entry> xfrm_bundle_create(Ptr<xfrm_policy> policy,
      Ptr<Ptr<xfrm_state>> xfrm, Ptr<Ptr<xfrm_dst>> bundle, int nx, Ptr<flowi> fl,
      Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_bundle_ok(Ptr<xfrm_dst> first) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_confirm_neigh((const struct dst_entry*)$arg1, (const void*)$arg2)")
  public static void xfrm_confirm_neigh(Ptr<dst_entry> dst, Ptr<?> daddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_default_advmss((const struct dst_entry*)$arg1)")
  public static @Unsigned int xfrm_default_advmss(Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_dev_backlog(Ptr<softnet_data> sd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_dev_event(Ptr<notifier_block> _this, @Unsigned long event, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_dev_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean xfrm_dev_offload_ok(Ptr<sk_buff> skb, Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_dev_policy_add(Ptr<net> net, Ptr<xfrm_policy> xp,
      Ptr<xfrm_user_offload> xuo, char dir, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_dev_policy_flush(Ptr<net> net, Ptr<net_device> dev, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_dev_resume(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_dev_state_add(Ptr<net> net, Ptr<xfrm_state> x, Ptr<xfrm_user_offload> xuo,
      Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_dev_state_delete(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_dev_state_flush(Ptr<net> net, Ptr<net_device> dev, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_dev_state_free(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dst_entry> xfrm_dst_check(Ptr<dst_entry> dst, @Unsigned int cookie) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_dst_hash_transfer(Ptr<net> net, Ptr<hlist_head> list,
      Ptr<hlist_head> ndsttable, @Unsigned int nhashmask, int dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_dst_ifdown(Ptr<dst_entry> dst, Ptr<net_device> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dst_entry> xfrm_dst_lookup(Ptr<xfrm_state> x, @OriginalName("dscp_t") char dscp,
      int oif, Ptr<xfrm_address_t> prev_saddr, Ptr<xfrm_address_t> prev_daddr, int family,
      @Unsigned int mark) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_find_acq($arg1, (const struct xfrm_mark*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg8, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg9, $arg10, $arg11)")
  public static Ptr<xfrm_state> xfrm_find_acq(Ptr<net> net, Ptr<xfrm_mark> mark, char mode,
      @Unsigned int reqid, @Unsigned int if_id, @Unsigned int pcpu_num, char proto,
      Ptr<xfrm_address_t> daddr, Ptr<xfrm_address_t> saddr, int create, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_state> xfrm_find_acq_byseq(Ptr<net> net, @Unsigned int mark,
      @Unsigned int seq, @Unsigned int pcpu_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_flowi_addr_get((const struct flowi*)$arg1, $arg2, $arg3, $arg4)")
  public static void xfrm_flowi_addr_get(Ptr<flowi> fl, Ptr<xfrm_address_t> saddr,
      Ptr<xfrm_address_t> daddr, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_flush_gc() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xfrm_gen_index(Ptr<net> net, int dir, @Unsigned int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xfrm_get_acqseq() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_translator> xfrm_get_translator() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<hlist_head> xfrm_hash_alloc(@Unsigned int sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_hash_free(Ptr<hlist_head> n, @Unsigned int sz) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_hash_rebuild(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_hash_resize(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_icmp_flow_decode($arg1, $arg2, (const struct flowi*)$arg3, $arg4)")
  public static boolean xfrm_icmp_flow_decode(Ptr<sk_buff> skb, @Unsigned short family,
      Ptr<flowi> fl, Ptr<flowi> fl1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_if_register_cb((const struct xfrm_if_cb*)$arg1)")
  public static void xfrm_if_register_cb(Ptr<xfrm_if_cb> ifcb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_if_unregister_cb() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_in_fwd_icmp($arg1, (const struct flowi*)$arg2, $arg3, $arg4)")
  public static Ptr<xfrm_policy> xfrm_in_fwd_icmp(Ptr<sk_buff> skb, Ptr<flowi> fl,
      @Unsigned short family, @Unsigned int if_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_init_replay(Ptr<xfrm_state> x, Ptr<netlink_ext_ack> extack) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_init_state(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_init_tempstate($arg1, (const struct flowi*)$arg2, (const struct xfrm_tmpl*)$arg3, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg4, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg5, $arg6)")
  public static void xfrm_init_tempstate(Ptr<xfrm_state> x, Ptr<flowi> fl, Ptr<xfrm_tmpl> tmpl,
      Ptr<xfrm_address_t> daddr, Ptr<xfrm_address_t> saddr, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_inner_extract_output(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_inner_mode_input(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_input(Ptr<sk_buff> skb, int nexthdr,
      @Unsigned @OriginalName("__be32") int spi, int encap_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_input_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_input_register_afinfo((const struct xfrm_input_afinfo*)$arg1)")
  public static int xfrm_input_register_afinfo(Ptr<xfrm_input_afinfo> afinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_input_resume(Ptr<sk_buff> skb, int nexthdr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_input_state_lookup($arg1, $arg2, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg3, $arg4, $arg5, $arg6)")
  public static Ptr<xfrm_state> xfrm_input_state_lookup(Ptr<net> net, @Unsigned int mark,
      Ptr<xfrm_address_t> daddr, @Unsigned @OriginalName("__be32") int spi, char proto,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_input_unregister_afinfo((const struct xfrm_input_afinfo*)$arg1)")
  public static int xfrm_input_unregister_afinfo(Ptr<xfrm_input_afinfo> afinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_link_failure(Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_local_error(Ptr<sk_buff> skb, int mtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_lookup($arg1, $arg2, (const struct flowi*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static Ptr<dst_entry> xfrm_lookup(Ptr<net> net, Ptr<dst_entry> dst_orig, Ptr<flowi> fl,
      Ptr<sock> sk, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_lookup_route($arg1, $arg2, (const struct flowi*)$arg3, (const struct sock*)$arg4, $arg5)")
  public static Ptr<dst_entry> xfrm_lookup_route(Ptr<net> net, Ptr<dst_entry> dst_orig,
      Ptr<flowi> fl, Ptr<sock> sk, int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_lookup_with_ifid($arg1, $arg2, (const struct flowi*)$arg3, (const struct sock*)$arg4, $arg5, $arg6)")
  public static Ptr<dst_entry> xfrm_lookup_with_ifid(Ptr<net> net, Ptr<dst_entry> dst_orig,
      Ptr<flowi> fl, Ptr<sock> sk, int flags, @Unsigned int if_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_mtu((const struct dst_entry*)$arg1)")
  public static @Unsigned int xfrm_mtu(Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_nat_keepalive_fini(@Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_nat_keepalive_init(@Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_nat_keepalive_net_fini(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_nat_keepalive_net_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_nat_keepalive_state_updated(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_negative_advice(Ptr<sock> sk, Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_neigh_lookup((const struct dst_entry*)$arg1, $arg2, (const void*)$arg3)")
  public static Ptr<neighbour> xfrm_neigh_lookup(Ptr<dst_entry> dst, Ptr<sk_buff> skb,
      Ptr<?> daddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_net_exit(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_net_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<dst_entry> xfrm_out_fwd_icmp(Ptr<sk_buff> skb, Ptr<flowi> fl,
      @Unsigned short family, Ptr<dst_entry> dst) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_outer_mode_output(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_outer_mode_prep(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_output(Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_output2(Ptr<net> net, Ptr<sock> sk, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_output_one(Ptr<sk_buff> skb, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_output_resume(Ptr<sock> sk, Ptr<sk_buff> skb, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_parse_spi(Ptr<sk_buff> skb, char nexthdr,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> spi,
      Ptr<java.lang. @Unsigned @OriginalName("__be32") Integer> seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_pol_bin_cmp($arg1, (const void*)$arg2)")
  public static int xfrm_pol_bin_cmp(Ptr<rhashtable_compare_arg> arg, Ptr<?> ptr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_pol_bin_key((const void*)$arg1, $arg2, $arg3)")
  public static @Unsigned int xfrm_pol_bin_key(Ptr<?> data, @Unsigned int len, @Unsigned int seed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_pol_bin_obj((const void*)$arg1, $arg2, $arg3)")
  public static @Unsigned int xfrm_pol_bin_obj(Ptr<?> data, @Unsigned int len, @Unsigned int seed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_pol_inexact_addr_use_any_list((const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg1, $arg2, $arg3)")
  public static boolean xfrm_pol_inexact_addr_use_any_list(Ptr<xfrm_address_t> addr, int family,
      char prefixlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_addr_delta((const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg1, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg2, $arg3, $arg4)")
  public static int xfrm_policy_addr_delta(Ptr<xfrm_address_t> a, Ptr<xfrm_address_t> b,
      char prefixlen, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_policy> xfrm_policy_alloc(Ptr<net> net,
      @Unsigned @OriginalName("gfp_t") int gfp) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_byid($arg1, (const struct xfrm_mark*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static Ptr<xfrm_policy> xfrm_policy_byid(Ptr<net> net, Ptr<xfrm_mark> mark,
      @Unsigned int if_id, char type, int dir, @Unsigned int id, int delete,
      Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_bysel_ctx($arg1, (const struct xfrm_mark*)$arg2, $arg3, $arg4, $arg5, $arg6, $arg7, $arg8, $arg9)")
  public static Ptr<xfrm_policy> xfrm_policy_bysel_ctx(Ptr<net> net, Ptr<xfrm_mark> mark,
      @Unsigned int if_id, char type, int dir, Ptr<xfrm_selector> sel, Ptr<xfrm_sec_ctx> ctx,
      int delete, Ptr<java.lang.Integer> err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_policy_delete(Ptr<xfrm_policy> pol, int dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_destroy(Ptr<xfrm_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_destroy_rcu(Ptr<callback_head> head) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_find_inexact_candidates($arg1, $arg2, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg3, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg4)")
  public static boolean xfrm_policy_find_inexact_candidates(Ptr<xfrm_pol_inexact_candidates> cand,
      Ptr<xfrm_pol_inexact_bin> b, Ptr<xfrm_address_t> saddr, Ptr<xfrm_address_t> daddr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_fini(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_policy_flush(Ptr<net> net, char type, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_hash_rebuild(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_inexact_alloc_bin((const struct xfrm_policy*)$arg1, $arg2)")
  public static Ptr<xfrm_pol_inexact_bin> xfrm_policy_inexact_alloc_bin(Ptr<xfrm_policy> pol,
      char dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<hlist_head> xfrm_policy_inexact_alloc_chain(Ptr<xfrm_pol_inexact_bin> bin,
      Ptr<xfrm_policy> policy, char dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_inexact_gc_tree(Ptr<rb_root> r, boolean rm) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_policy> xfrm_policy_inexact_insert(Ptr<xfrm_policy> policy, char dir,
      int excl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_pol_inexact_node> xfrm_policy_inexact_insert_node(Ptr<net> net,
      Ptr<rb_root> root, Ptr<xfrm_address_t> addr, @Unsigned short family, char prefixlen,
      char dir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_inexact_list_reinsert(Ptr<net> net, Ptr<xfrm_pol_inexact_node> n,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_inexact_node_merge(Ptr<net> net, Ptr<xfrm_pol_inexact_node> v,
      Ptr<xfrm_pol_inexact_node> n, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_policy_insert(int dir, Ptr<xfrm_policy> policy, int excl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_policy> xfrm_policy_insert_list(Ptr<hlist_head> chain,
      Ptr<xfrm_policy> policy, boolean excl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_kill(Ptr<xfrm_policy> policy) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_lookup_inexact_addr((const struct rb_root*)$arg1, $arg2, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg3, $arg4)")
  public static Ptr<xfrm_pol_inexact_node> xfrm_policy_lookup_inexact_addr(Ptr<rb_root> r,
      Ptr<@OriginalName("seqcount_spinlock_t") seqcount_spinlock> count, Ptr<xfrm_address_t> addr,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_ok((const struct xfrm_tmpl*)$arg1, (const struct sec_path*)$arg2, $arg3, $arg4, $arg5)")
  public static int xfrm_policy_ok(Ptr<xfrm_tmpl> tmpl, Ptr<sec_path> sp, int start,
      @Unsigned short family, @Unsigned int if_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_queue_process(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_register_afinfo((const struct xfrm_policy_afinfo*)$arg1, $arg2)")
  public static int xfrm_policy_register_afinfo(Ptr<xfrm_policy_afinfo> afinfo, int family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_requeue(Ptr<xfrm_policy> old, Ptr<xfrm_policy> _new) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_timer(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_policy_unregister_afinfo((const struct xfrm_policy_afinfo*)$arg1)")
  public static void xfrm_policy_unregister_afinfo(Ptr<xfrm_policy_afinfo> afinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_walk_done(Ptr<xfrm_policy_walk> walk, Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_policy_walk_init(Ptr<xfrm_policy_walk> walk, char type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_prepare_input(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_proc_fini(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_proc_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_put_translator(Ptr<xfrm_translator> xtr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_rcv_cb(Ptr<sk_buff> skb, @Unsigned int family, char protocol, int err) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_register_km(Ptr<xfrm_mgr> km) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_register_mode_cbs($arg1, (const struct xfrm_mode_cbs*)$arg2)")
  public static int xfrm_register_mode_cbs(char mode, Ptr<xfrm_mode_cbs> mode_cbs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_register_translator(Ptr<xfrm_translator> xtr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_register_type((const struct xfrm_type*)$arg1, $arg2)")
  public static int xfrm_register_type(Ptr<xfrm_type> type, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_register_type_offload((const struct xfrm_type_offload*)$arg1, $arg2)")
  public static int xfrm_register_type_offload(Ptr<xfrm_type_offload> type,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_replay_advance(Ptr<xfrm_state> x,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_replay_advance_esn(Ptr<xfrm_state> x,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_replay_check(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_replay_check_bmp(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_replay_check_esn(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_replay_check_legacy(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_replay_notify(Ptr<xfrm_state> x, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_replay_notify_bmp(Ptr<xfrm_state> x, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_replay_notify_esn(Ptr<xfrm_state> x, int event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_replay_overflow(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_replay_overflow_offload_esn(Ptr<xfrm_state> x, Ptr<sk_buff> skb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_replay_recheck(Ptr<xfrm_state> x, Ptr<sk_buff> skb,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xfrm_replay_seqhi(Ptr<xfrm_state> x,
      @Unsigned @OriginalName("__be32") int net_seq) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_replay_timer_handler(Ptr<timer_list> t) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_resolve_and_create_bundle($arg1, $arg2, (const struct flowi*)$arg3, $arg4, $arg5)")
  public static Ptr<xfrm_dst> xfrm_resolve_and_create_bundle(Ptr<Ptr<xfrm_policy>> pols,
      int num_pols, Ptr<flowi> fl, @Unsigned short family, Ptr<dst_entry> dst_orig) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_sad_getinfo(Ptr<net> net, Ptr<xfrmk_sadinfo> si) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_selector_inner_icmp_match($arg1, $arg2, (const struct xfrm_selector*)$arg3, (const struct flowi*)$arg4)")
  public static boolean xfrm_selector_inner_icmp_match(Ptr<sk_buff> skb, @Unsigned short family,
      Ptr<xfrm_selector> sel, Ptr<flowi> fl) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_selector_match((const struct xfrm_selector*)$arg1, (const struct flowi*)$arg2, $arg3)")
  public static boolean xfrm_selector_match(Ptr<xfrm_selector> sel, Ptr<flowi> fl,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_set_type_offload(Ptr<xfrm_state> x, boolean try_load) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_sk_policy_insert(Ptr<sock> sk, int dir, Ptr<xfrm_policy> pol) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_sk_policy_lookup((const struct sock*)$arg1, $arg2, (const struct flowi*)$arg3, $arg4, $arg5)")
  public static Ptr<xfrm_policy> xfrm_sk_policy_lookup(Ptr<sock> sk, int dir, Ptr<flowi> fl,
      @Unsigned short family, @Unsigned int if_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_spd_getinfo(Ptr<net> net, Ptr<xfrmk_spdinfo> si) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_add(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_state_afinfo> xfrm_state_afinfo_get_rcu(@Unsigned int family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_state> xfrm_state_alloc(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_check_expire(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_delete(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_state_find((const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg1, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg2, (const struct flowi*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static Ptr<xfrm_state> xfrm_state_find(Ptr<xfrm_address_t> daddr,
      Ptr<xfrm_address_t> saddr, Ptr<flowi> fl, Ptr<xfrm_tmpl> tmpl, Ptr<xfrm_policy> pol,
      Ptr<java.lang.Integer> err, @Unsigned short family, @Unsigned int if_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_state_fini(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_flush(Ptr<net> net, char proto, boolean task_valid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_state_free(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_state_gc_task(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_state_afinfo> xfrm_state_get_afinfo(@Unsigned int family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_state_insert(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_state_look_at($arg1, $arg2, (const struct flowi*)$arg3, $arg4, $arg5, $arg6, $arg7, $arg8)")
  public static void xfrm_state_look_at(Ptr<xfrm_policy> pol, Ptr<xfrm_state> x, Ptr<flowi> fl,
      @Unsigned short family, Ptr<Ptr<xfrm_state>> best, Ptr<java.lang.Integer> acq_in_progress,
      Ptr<java.lang.Integer> error, @Unsigned int pcpu_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_state_lookup($arg1, $arg2, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg3, $arg4, $arg5, $arg6)")
  public static Ptr<xfrm_state> xfrm_state_lookup(Ptr<net> net, @Unsigned int mark,
      Ptr<xfrm_address_t> daddr, @Unsigned @OriginalName("__be32") int spi, char proto,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_state_lookup_byaddr($arg1, $arg2, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg3, (const union {\n"
          + "  unsigned int a4;\n"
          + "  unsigned int a6[4];\n"
          + "  struct in6_addr in6;\n"
          + "}*)$arg4, $arg5, $arg6)")
  public static Ptr<xfrm_state> xfrm_state_lookup_byaddr(Ptr<net> net, @Unsigned int mark,
      Ptr<xfrm_address_t> daddr, Ptr<xfrm_address_t> saddr, char proto, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_state> xfrm_state_lookup_byspi(Ptr<net> net,
      @Unsigned @OriginalName("__be32") int spi, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xfrm_state_mtu(Ptr<xfrm_state> x, int mtu) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_register_afinfo(Ptr<xfrm_state_afinfo> afinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_unregister_afinfo(Ptr<xfrm_state_afinfo> afinfo) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_state_update(Ptr<xfrm_state> x) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_state_update_stats(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_state_walk_done(Ptr<xfrm_state_walk> walk, Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_state_walk_init(Ptr<xfrm_state_walk> walk, char proto,
      Ptr<xfrm_address_filter> filter) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xfrm_state> xfrm_stateonly_find(Ptr<net> net, @Unsigned int mark,
      @Unsigned int if_id, Ptr<xfrm_address_t> daddr, Ptr<xfrm_address_t> saddr,
      @Unsigned short family, char mode, char proto, @Unsigned int reqid) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_statistics_seq_show(Ptr<seq_file> seq, Ptr<?> v) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_sysctl_fini(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_sysctl_init(Ptr<net> net) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static hrtimer_restart xfrm_timer_handler(Ptr<hrtimer> me) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_tmpl_resolve($arg1, $arg2, (const struct flowi*)$arg3, $arg4, $arg5)")
  public static int xfrm_tmpl_resolve(Ptr<Ptr<xfrm_policy>> pols, int npols, Ptr<flowi> fl,
      Ptr<Ptr<xfrm_state>> xfrm, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_tmpl_resolve_one($arg1, (const struct flowi*)$arg2, $arg3, $arg4)")
  public static int xfrm_tmpl_resolve_one(Ptr<xfrm_policy> policy, Ptr<flowi> fl,
      Ptr<Ptr<xfrm_state>> xfrm, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_trans_queue($arg1, (int (*)(struct net*, struct sock*, struct sk_buff*))$arg2)")
  public static int xfrm_trans_queue(Ptr<sk_buff> skb, Ptr<?> finish) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_trans_queue_net($arg1, $arg2, (int (*)(struct net*, struct sock*, struct sk_buff*))$arg3)")
  public static int xfrm_trans_queue_net(Ptr<net> net, Ptr<sk_buff> skb, Ptr<?> finish) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_trans_reinject(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_unregister_km(Ptr<xfrm_mgr> km) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xfrm_unregister_mode_cbs(char mode) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_unregister_translator(Ptr<xfrm_translator> xtr) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_unregister_type((const struct xfrm_type*)$arg1, $arg2)")
  public static void xfrm_unregister_type(Ptr<xfrm_type> type, @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xfrm_unregister_type_offload((const struct xfrm_type_offload*)$arg1, $arg2)")
  public static void xfrm_unregister_type_offload(Ptr<xfrm_type_offload> type,
      @Unsigned short family) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xfrm_user_policy(Ptr<sock> sk, int optname, sockptr_t optval, int optlen) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_policy_hash"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_policy_hash extends Struct {
    public Ptr<hlist_head> table;

    public @Unsigned int hmask;

    public char dbits4;

    public char sbits4;

    public char dbits6;

    public char sbits6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_policy_hthresh"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_policy_hthresh extends Struct {
    public work_struct work;

    public seqlock_t lock;

    public char lbits4;

    public char rbits4;

    public char lbits6;

    public char rbits6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union { unsigned int a4; unsigned int a6[4]; struct in6_addr in6; }"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_address_t extends Union {
    public @Unsigned @OriginalName("__be32") int a4;

    public @Unsigned @OriginalName("__be32") int @Size(4) [] a6;

    public in6_addr in6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_id"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_id extends Struct {
    public xfrm_address_t daddr;

    public @Unsigned @OriginalName("__be32") int spi;

    public char proto;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_sec_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_sec_ctx extends Struct {
    public char ctx_doi;

    public char ctx_alg;

    public @Unsigned short ctx_len;

    public @Unsigned int ctx_sid;

    public char @Size(0) [] ctx_str;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_selector"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_selector extends Struct {
    public xfrm_address_t daddr;

    public xfrm_address_t saddr;

    public @Unsigned @OriginalName("__be16") short dport;

    public @Unsigned @OriginalName("__be16") short dport_mask;

    public @Unsigned @OriginalName("__be16") short sport;

    public @Unsigned @OriginalName("__be16") short sport_mask;

    public @Unsigned short family;

    public char prefixlen_d;

    public char prefixlen_s;

    public char proto;

    public int ifindex;

    public @Unsigned @OriginalName("__kernel_uid32_t") int user;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_lifetime_cfg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_lifetime_cfg extends Struct {
    public @Unsigned long soft_byte_limit;

    public @Unsigned long hard_byte_limit;

    public @Unsigned long soft_packet_limit;

    public @Unsigned long hard_packet_limit;

    public @Unsigned long soft_add_expires_seconds;

    public @Unsigned long hard_add_expires_seconds;

    public @Unsigned long soft_use_expires_seconds;

    public @Unsigned long hard_use_expires_seconds;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_lifetime_cur"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_lifetime_cur extends Struct {
    public @Unsigned long bytes;

    public @Unsigned long packets;

    public @Unsigned long add_time;

    public @Unsigned long use_time;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_replay_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_replay_state extends Struct {
    public @Unsigned int oseq;

    public @Unsigned int seq;

    public @Unsigned int bitmap;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_replay_state_esn"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_replay_state_esn extends Struct {
    public @Unsigned int bmp_len;

    public @Unsigned int oseq;

    public @Unsigned int seq;

    public @Unsigned int oseq_hi;

    public @Unsigned int seq_hi;

    public @Unsigned int replay_window;

    public @Unsigned int @Size(0) [] bmp;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_algo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_algo extends Struct {
    public char @Size(64) [] alg_name;

    public @Unsigned int alg_key_len;

    public char @Size(0) [] alg_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_algo_auth"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_algo_auth extends Struct {
    public char @Size(64) [] alg_name;

    public @Unsigned int alg_key_len;

    public @Unsigned int alg_trunc_len;

    public char @Size(0) [] alg_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_algo_aead"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_algo_aead extends Struct {
    public char @Size(64) [] alg_name;

    public @Unsigned int alg_key_len;

    public @Unsigned int alg_icv_len;

    public char @Size(0) [] alg_key;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_stats"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_stats extends Struct {
    public @Unsigned int replay_window;

    public @Unsigned int replay;

    public @Unsigned int integrity_failed;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_encap_tmpl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_encap_tmpl extends Struct {
    public @Unsigned short encap_type;

    public @Unsigned @OriginalName("__be16") short encap_sport;

    public @Unsigned @OriginalName("__be16") short encap_dport;

    public xfrm_address_t encap_oa;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xfrm_attr_type_t"
  )
  public enum xfrm_attr_type_t implements Enum<xfrm_attr_type_t>, TypedEnum<xfrm_attr_type_t, java.lang. @Unsigned Integer> {
    /**
     * {@code XFRMA_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XFRMA_UNSPEC"
    )
    XFRMA_UNSPEC,

    /**
     * {@code XFRMA_ALG_AUTH = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XFRMA_ALG_AUTH"
    )
    XFRMA_ALG_AUTH,

    /**
     * {@code XFRMA_ALG_CRYPT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "XFRMA_ALG_CRYPT"
    )
    XFRMA_ALG_CRYPT,

    /**
     * {@code XFRMA_ALG_COMP = 3}
     */
    @EnumMember(
        value = 3L,
        name = "XFRMA_ALG_COMP"
    )
    XFRMA_ALG_COMP,

    /**
     * {@code XFRMA_ENCAP = 4}
     */
    @EnumMember(
        value = 4L,
        name = "XFRMA_ENCAP"
    )
    XFRMA_ENCAP,

    /**
     * {@code XFRMA_TMPL = 5}
     */
    @EnumMember(
        value = 5L,
        name = "XFRMA_TMPL"
    )
    XFRMA_TMPL,

    /**
     * {@code XFRMA_SA = 6}
     */
    @EnumMember(
        value = 6L,
        name = "XFRMA_SA"
    )
    XFRMA_SA,

    /**
     * {@code XFRMA_POLICY = 7}
     */
    @EnumMember(
        value = 7L,
        name = "XFRMA_POLICY"
    )
    XFRMA_POLICY,

    /**
     * {@code XFRMA_SEC_CTX = 8}
     */
    @EnumMember(
        value = 8L,
        name = "XFRMA_SEC_CTX"
    )
    XFRMA_SEC_CTX,

    /**
     * {@code XFRMA_LTIME_VAL = 9}
     */
    @EnumMember(
        value = 9L,
        name = "XFRMA_LTIME_VAL"
    )
    XFRMA_LTIME_VAL,

    /**
     * {@code XFRMA_REPLAY_VAL = 10}
     */
    @EnumMember(
        value = 10L,
        name = "XFRMA_REPLAY_VAL"
    )
    XFRMA_REPLAY_VAL,

    /**
     * {@code XFRMA_REPLAY_THRESH = 11}
     */
    @EnumMember(
        value = 11L,
        name = "XFRMA_REPLAY_THRESH"
    )
    XFRMA_REPLAY_THRESH,

    /**
     * {@code XFRMA_ETIMER_THRESH = 12}
     */
    @EnumMember(
        value = 12L,
        name = "XFRMA_ETIMER_THRESH"
    )
    XFRMA_ETIMER_THRESH,

    /**
     * {@code XFRMA_SRCADDR = 13}
     */
    @EnumMember(
        value = 13L,
        name = "XFRMA_SRCADDR"
    )
    XFRMA_SRCADDR,

    /**
     * {@code XFRMA_COADDR = 14}
     */
    @EnumMember(
        value = 14L,
        name = "XFRMA_COADDR"
    )
    XFRMA_COADDR,

    /**
     * {@code XFRMA_LASTUSED = 15}
     */
    @EnumMember(
        value = 15L,
        name = "XFRMA_LASTUSED"
    )
    XFRMA_LASTUSED,

    /**
     * {@code XFRMA_POLICY_TYPE = 16}
     */
    @EnumMember(
        value = 16L,
        name = "XFRMA_POLICY_TYPE"
    )
    XFRMA_POLICY_TYPE,

    /**
     * {@code XFRMA_MIGRATE = 17}
     */
    @EnumMember(
        value = 17L,
        name = "XFRMA_MIGRATE"
    )
    XFRMA_MIGRATE,

    /**
     * {@code XFRMA_ALG_AEAD = 18}
     */
    @EnumMember(
        value = 18L,
        name = "XFRMA_ALG_AEAD"
    )
    XFRMA_ALG_AEAD,

    /**
     * {@code XFRMA_KMADDRESS = 19}
     */
    @EnumMember(
        value = 19L,
        name = "XFRMA_KMADDRESS"
    )
    XFRMA_KMADDRESS,

    /**
     * {@code XFRMA_ALG_AUTH_TRUNC = 20}
     */
    @EnumMember(
        value = 20L,
        name = "XFRMA_ALG_AUTH_TRUNC"
    )
    XFRMA_ALG_AUTH_TRUNC,

    /**
     * {@code XFRMA_MARK = 21}
     */
    @EnumMember(
        value = 21L,
        name = "XFRMA_MARK"
    )
    XFRMA_MARK,

    /**
     * {@code XFRMA_TFCPAD = 22}
     */
    @EnumMember(
        value = 22L,
        name = "XFRMA_TFCPAD"
    )
    XFRMA_TFCPAD,

    /**
     * {@code XFRMA_REPLAY_ESN_VAL = 23}
     */
    @EnumMember(
        value = 23L,
        name = "XFRMA_REPLAY_ESN_VAL"
    )
    XFRMA_REPLAY_ESN_VAL,

    /**
     * {@code XFRMA_SA_EXTRA_FLAGS = 24}
     */
    @EnumMember(
        value = 24L,
        name = "XFRMA_SA_EXTRA_FLAGS"
    )
    XFRMA_SA_EXTRA_FLAGS,

    /**
     * {@code XFRMA_PROTO = 25}
     */
    @EnumMember(
        value = 25L,
        name = "XFRMA_PROTO"
    )
    XFRMA_PROTO,

    /**
     * {@code XFRMA_ADDRESS_FILTER = 26}
     */
    @EnumMember(
        value = 26L,
        name = "XFRMA_ADDRESS_FILTER"
    )
    XFRMA_ADDRESS_FILTER,

    /**
     * {@code XFRMA_PAD = 27}
     */
    @EnumMember(
        value = 27L,
        name = "XFRMA_PAD"
    )
    XFRMA_PAD,

    /**
     * {@code XFRMA_OFFLOAD_DEV = 28}
     */
    @EnumMember(
        value = 28L,
        name = "XFRMA_OFFLOAD_DEV"
    )
    XFRMA_OFFLOAD_DEV,

    /**
     * {@code XFRMA_SET_MARK = 29}
     */
    @EnumMember(
        value = 29L,
        name = "XFRMA_SET_MARK"
    )
    XFRMA_SET_MARK,

    /**
     * {@code XFRMA_SET_MARK_MASK = 30}
     */
    @EnumMember(
        value = 30L,
        name = "XFRMA_SET_MARK_MASK"
    )
    XFRMA_SET_MARK_MASK,

    /**
     * {@code XFRMA_IF_ID = 31}
     */
    @EnumMember(
        value = 31L,
        name = "XFRMA_IF_ID"
    )
    XFRMA_IF_ID,

    /**
     * {@code XFRMA_MTIMER_THRESH = 32}
     */
    @EnumMember(
        value = 32L,
        name = "XFRMA_MTIMER_THRESH"
    )
    XFRMA_MTIMER_THRESH,

    /**
     * {@code XFRMA_SA_DIR = 33}
     */
    @EnumMember(
        value = 33L,
        name = "XFRMA_SA_DIR"
    )
    XFRMA_SA_DIR,

    /**
     * {@code XFRMA_NAT_KEEPALIVE_INTERVAL = 34}
     */
    @EnumMember(
        value = 34L,
        name = "XFRMA_NAT_KEEPALIVE_INTERVAL"
    )
    XFRMA_NAT_KEEPALIVE_INTERVAL,

    /**
     * {@code XFRMA_SA_PCPU = 35}
     */
    @EnumMember(
        value = 35L,
        name = "XFRMA_SA_PCPU"
    )
    XFRMA_SA_PCPU,

    /**
     * {@code XFRMA_IPTFS_DROP_TIME = 36}
     */
    @EnumMember(
        value = 36L,
        name = "XFRMA_IPTFS_DROP_TIME"
    )
    XFRMA_IPTFS_DROP_TIME,

    /**
     * {@code XFRMA_IPTFS_REORDER_WINDOW = 37}
     */
    @EnumMember(
        value = 37L,
        name = "XFRMA_IPTFS_REORDER_WINDOW"
    )
    XFRMA_IPTFS_REORDER_WINDOW,

    /**
     * {@code XFRMA_IPTFS_DONT_FRAG = 38}
     */
    @EnumMember(
        value = 38L,
        name = "XFRMA_IPTFS_DONT_FRAG"
    )
    XFRMA_IPTFS_DONT_FRAG,

    /**
     * {@code XFRMA_IPTFS_INIT_DELAY = 39}
     */
    @EnumMember(
        value = 39L,
        name = "XFRMA_IPTFS_INIT_DELAY"
    )
    XFRMA_IPTFS_INIT_DELAY,

    /**
     * {@code XFRMA_IPTFS_MAX_QSIZE = 40}
     */
    @EnumMember(
        value = 40L,
        name = "XFRMA_IPTFS_MAX_QSIZE"
    )
    XFRMA_IPTFS_MAX_QSIZE,

    /**
     * {@code XFRMA_IPTFS_PKT_SIZE = 41}
     */
    @EnumMember(
        value = 41L,
        name = "XFRMA_IPTFS_PKT_SIZE"
    )
    XFRMA_IPTFS_PKT_SIZE,

    /**
     * {@code __XFRMA_MAX = 42}
     */
    @EnumMember(
        value = 42L,
        name = "__XFRMA_MAX"
    )
    __XFRMA_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_mark"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_mark extends Struct {
    public @Unsigned int v;

    public @Unsigned int m;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_address_filter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_address_filter extends Struct {
    public xfrm_address_t saddr;

    public xfrm_address_t daddr;

    public @Unsigned short family;

    public char splen;

    public char dplen;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_state extends Struct {
    public possible_net_t xs_net;

    @InlineUnion(17586)
    public hlist_node gclist;

    @InlineUnion(17586)
    public hlist_node bydst;

    @InlineUnion(17587)
    public hlist_node dev_gclist;

    @InlineUnion(17587)
    public hlist_node bysrc;

    public hlist_node byspi;

    public hlist_node byseq;

    public hlist_node state_cache;

    public hlist_node state_cache_input;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned int pcpu_num;

    public xfrm_id id;

    public xfrm_selector sel;

    public xfrm_mark mark;

    public @Unsigned int if_id;

    public @Unsigned int tfcpad;

    public @Unsigned int genid;

    public xfrm_state_walk km;

    public props_of_xfrm_state props;

    public xfrm_lifetime_cfg lft;

    public Ptr<xfrm_algo_auth> aalg;

    public Ptr<xfrm_algo> ealg;

    public Ptr<xfrm_algo> calg;

    public Ptr<xfrm_algo_aead> aead;

    public String geniv;

    public @Unsigned @OriginalName("__be16") short new_mapping_sport;

    public @Unsigned int new_mapping;

    public @Unsigned int mapping_maxage;

    public Ptr<xfrm_encap_tmpl> encap;

    public @Unsigned int nat_keepalive_interval;

    public @OriginalName("time64_t") long nat_keepalive_expiration;

    public Ptr<xfrm_address_t> coaddr;

    public Ptr<xfrm_state> tunnel;

    public atomic_t tunnel_users;

    public xfrm_replay_state replay;

    public Ptr<xfrm_replay_state_esn> replay_esn;

    public xfrm_replay_state preplay;

    public Ptr<xfrm_replay_state_esn> preplay_esn;

    public xfrm_replay_mode repl_mode;

    public @Unsigned int xflags;

    public @Unsigned int replay_maxage;

    public @Unsigned int replay_maxdiff;

    public timer_list rtimer;

    public xfrm_stats stats;

    public xfrm_lifetime_cur curlft;

    public hrtimer mtimer;

    public xfrm_dev_offload xso;

    public long saved_tmo;

    public @OriginalName("time64_t") long lastused;

    public page_frag xfrag;

    public Ptr<xfrm_type> type;

    public xfrm_mode inner_mode;

    public xfrm_mode inner_mode_iaf;

    public xfrm_mode outer_mode;

    public Ptr<xfrm_type_offload> type_offload;

    public Ptr<xfrm_sec_ctx> security;

    public Ptr<?> data;

    public char dir;

    public Ptr<xfrm_mode_cbs> mode_cbs;

    public Ptr<?> mode_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_policy"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_policy extends Struct {
    public possible_net_t xp_net;

    public hlist_node bydst;

    public hlist_node byidx;

    public hlist_head state_cache_list;

    public rwlock_t lock;

    public @OriginalName("refcount_t") refcount_struct refcnt;

    public @Unsigned int pos;

    public timer_list timer;

    public atomic_t genid;

    public @Unsigned int priority;

    public @Unsigned int index;

    public @Unsigned int if_id;

    public xfrm_mark mark;

    public xfrm_selector selector;

    public xfrm_lifetime_cfg lft;

    public xfrm_lifetime_cur curlft;

    public xfrm_policy_walk_entry walk;

    public xfrm_policy_queue polq;

    public boolean bydst_reinsert;

    public char type;

    public char action;

    public char flags;

    public char xfrm_nr;

    public @Unsigned short family;

    public Ptr<xfrm_sec_ctx> security;

    public xfrm_tmpl @Size(6) [] xfrm_vec;

    public callback_head rcu;

    public xfrm_dev_offload xdo;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_state_walk"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_state_walk extends Struct {
    public list_head all;

    public char state;

    public char dying;

    public char proto;

    public @Unsigned int seq;

    public Ptr<xfrm_address_filter> filter;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_dev_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_dev_offload extends Struct {
    public Ptr<net_device> dev;

    public @OriginalName("netdevice_tracker") lockdep_map_p dev_tracker;

    public Ptr<net_device> real_dev;

    public @Unsigned long offload_handle;

    public char dir;

    public char type;

    public char flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_mode"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_mode extends Struct {
    public char encap;

    public char family;

    public char flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xfrm_replay_mode"
  )
  public enum xfrm_replay_mode implements Enum<xfrm_replay_mode>, TypedEnum<xfrm_replay_mode, java.lang. @Unsigned Integer> {
    /**
     * {@code XFRM_REPLAY_MODE_LEGACY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XFRM_REPLAY_MODE_LEGACY"
    )
    XFRM_REPLAY_MODE_LEGACY,

    /**
     * {@code XFRM_REPLAY_MODE_BMP = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XFRM_REPLAY_MODE_BMP"
    )
    XFRM_REPLAY_MODE_BMP,

    /**
     * {@code XFRM_REPLAY_MODE_ESN = 2}
     */
    @EnumMember(
        value = 2L,
        name = "XFRM_REPLAY_MODE_ESN"
    )
    XFRM_REPLAY_MODE_ESN
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_type"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_type extends Struct {
    public Ptr<module> owner;

    public char proto;

    public char flags;

    public Ptr<?> init_state;

    public Ptr<?> destructor;

    public Ptr<?> input;

    public Ptr<?> output;

    public Ptr<?> reject;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_type_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_type_offload extends Struct {
    public Ptr<module> owner;

    public char proto;

    public Ptr<?> encap;

    public Ptr<?> input_tail;

    public Ptr<?> xmit;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_mode_cbs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_mode_cbs extends Struct {
    public Ptr<module> owner;

    public Ptr<?> init_state;

    public Ptr<?> clone_state;

    public Ptr<?> destroy_state;

    public Ptr<?> user_init;

    public Ptr<?> copy_to_user;

    public Ptr<?> sa_len;

    public Ptr<?> get_inner_mtu;

    public Ptr<?> input;

    public Ptr<?> output;

    public Ptr<?> prepare_output;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_tmpl"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_tmpl extends Struct {
    public xfrm_id id;

    public xfrm_address_t saddr;

    public @Unsigned short encap_family;

    public @Unsigned int reqid;

    public char mode;

    public char share;

    public char optional;

    public char allalgs;

    public @Unsigned int aalgos;

    public @Unsigned int ealgos;

    public @Unsigned int calgos;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_policy_walk_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_policy_walk_entry extends Struct {
    public list_head all;

    public char dead;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_policy_queue"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_policy_queue extends Struct {
    public sk_buff_head hold_queue;

    public timer_list hold_timer;

    public @Unsigned long timeout;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_user_sec_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_user_sec_ctx extends Struct {
    public @Unsigned short len;

    public @Unsigned short exttype;

    public char ctx_alg;

    public char ctx_doi;

    public @Unsigned short ctx_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_dst"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_dst extends Struct {
    public u_of_xfrm_dst u;

    public Ptr<dst_entry> route;

    public Ptr<dst_entry> child;

    public Ptr<dst_entry> path;

    public Ptr<xfrm_policy> @Size(2) [] pols;

    public int num_pols;

    public int num_xfrms;

    public @Unsigned int xfrm_genid;

    public @Unsigned int policy_genid;

    public @Unsigned int route_mtu_cached;

    public @Unsigned int child_mtu_cached;

    public @Unsigned int route_cookie;

    public @Unsigned int path_cookie;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_offload extends Struct {
    public output_of_seq_of_xfrm_skb_cb_and_seq_of_xfrm_offload seq;

    public @Unsigned int flags;

    public @Unsigned int status;

    public @Unsigned int orig_mac_len;

    public char proto;

    public char inner_ipproto;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_md_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_md_info extends Struct {
    public @Unsigned int if_id;

    public int link;

    public Ptr<dst_entry> dst_orig;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_dst_lookup_params"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_dst_lookup_params extends Struct {
    public Ptr<net> net;

    public @OriginalName("dscp_t") char dscp;

    public int oif;

    public Ptr<xfrm_address_t> saddr;

    public Ptr<xfrm_address_t> daddr;

    public @Unsigned int mark;

    public char ipproto;

    public flowi_uli uli;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_policy_afinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_policy_afinfo extends Struct {
    public Ptr<dst_ops> dst_ops;

    public Ptr<?> dst_lookup;

    public Ptr<?> get_saddr;

    public Ptr<?> fill_dst;

    public Ptr<?> blackhole_route;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_state_afinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_state_afinfo extends Struct {
    public char family;

    public char proto;

    public Ptr<xfrm_type_offload> type_offload_esp;

    public Ptr<xfrm_type> type_esp;

    public Ptr<xfrm_type> type_ipip;

    public Ptr<xfrm_type> type_ipip6;

    public Ptr<xfrm_type> type_comp;

    public Ptr<xfrm_type> type_ah;

    public Ptr<xfrm_type> type_routing;

    public Ptr<xfrm_type> type_dstopts;

    public Ptr<?> output;

    public Ptr<?> transport_finish;

    public Ptr<?> local_error;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_tunnel_skb_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_tunnel_skb_cb extends Struct {
    public anon_member_of_ipfrag_skb_cb_and_header_of_anon_member_of_tcp_skb_cb_and_header_of_sock_exterr_skb header;

    public tunnel_of_xfrm_tunnel_skb_cb tunnel;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_mode_skb_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_mode_skb_cb extends Struct {
    public xfrm_tunnel_skb_cb header;

    public @Unsigned @OriginalName("__be16") short id;

    public @Unsigned @OriginalName("__be16") short frag_off;

    public char ihl;

    public char tos;

    public char ttl;

    public char protocol;

    public char optlen;

    public char @Size(3) [] flow_lbl;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_spi_skb_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_spi_skb_cb extends Struct {
    public xfrm_tunnel_skb_cb header;

    public @Unsigned int daddroff;

    public @Unsigned int family;

    public @Unsigned @OriginalName("__be32") int seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_input_afinfo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_input_afinfo extends Struct {
    public char family;

    public boolean is_ipip;

    public Ptr<?> callback;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xfrm_sa_dir"
  )
  public enum xfrm_sa_dir implements Enum<xfrm_sa_dir>, TypedEnum<xfrm_sa_dir, java.lang. @Unsigned Integer> {
    /**
     * {@code XFRM_SA_DIR_IN = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XFRM_SA_DIR_IN"
    )
    XFRM_SA_DIR_IN,

    /**
     * {@code XFRM_SA_DIR_OUT = 2}
     */
    @EnumMember(
        value = 2L,
        name = "XFRM_SA_DIR_OUT"
    )
    XFRM_SA_DIR_OUT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_if_decode_session_result"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_if_decode_session_result extends Struct {
    public Ptr<net> net;

    public @Unsigned int if_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_if_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_if_cb extends Struct {
    public Ptr<?> decode_session;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_policy_walk"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_policy_walk extends Struct {
    public xfrm_policy_walk_entry walk;

    public char type;

    public @Unsigned int seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_flo"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_flo extends Struct {
    public Ptr<dst_entry> dst_orig;

    public char flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_pol_inexact_node"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_pol_inexact_node extends Struct {
    public rb_node node;

    @InlineUnion(62665)
    public xfrm_address_t addr;

    @InlineUnion(62665)
    public callback_head rcu;

    public char prefixlen;

    public rb_root root;

    public hlist_head hhead;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_pol_inexact_key"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_pol_inexact_key extends Struct {
    public possible_net_t net;

    public @Unsigned int if_id;

    public @Unsigned short family;

    public char dir;

    public char type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_pol_inexact_bin"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_pol_inexact_bin extends Struct {
    public xfrm_pol_inexact_key k;

    public rhash_head head;

    public hlist_head hhead;

    public @OriginalName("seqcount_spinlock_t") seqcount_spinlock count;

    public rb_root root_d;

    public rb_root root_s;

    public list_head inexact_bins;

    public callback_head rcu;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xfrm_pol_inexact_candidate_type"
  )
  public enum xfrm_pol_inexact_candidate_type implements Enum<xfrm_pol_inexact_candidate_type>, TypedEnum<xfrm_pol_inexact_candidate_type, java.lang. @Unsigned Integer> {
    /**
     * {@code XFRM_POL_CAND_BOTH = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XFRM_POL_CAND_BOTH"
    )
    XFRM_POL_CAND_BOTH,

    /**
     * {@code XFRM_POL_CAND_SADDR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XFRM_POL_CAND_SADDR"
    )
    XFRM_POL_CAND_SADDR,

    /**
     * {@code XFRM_POL_CAND_DADDR = 2}
     */
    @EnumMember(
        value = 2L,
        name = "XFRM_POL_CAND_DADDR"
    )
    XFRM_POL_CAND_DADDR,

    /**
     * {@code XFRM_POL_CAND_ANY = 3}
     */
    @EnumMember(
        value = 3L,
        name = "XFRM_POL_CAND_ANY"
    )
    XFRM_POL_CAND_ANY,

    /**
     * {@code XFRM_POL_CAND_MAX = 4}
     */
    @EnumMember(
        value = 4L,
        name = "XFRM_POL_CAND_MAX"
    )
    XFRM_POL_CAND_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_pol_inexact_candidates"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_pol_inexact_candidates extends Struct {
    public Ptr<hlist_head> @Size(4) [] res;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_flow_keys"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_flow_keys extends Struct {
    public flow_dissector_key_basic basic;

    public flow_dissector_key_control control;

    public addrs_of_xfrm_flow_keys_and_anon_member_of_ethtool_rx_flow_key addrs;

    public flow_dissector_key_ip ip;

    public flow_dissector_key_icmp icmp;

    public flow_dissector_key_ports ports;

    public flow_dissector_key_keyid gre;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xfrm_ae_ftype_t"
  )
  public enum xfrm_ae_ftype_t implements Enum<xfrm_ae_ftype_t>, TypedEnum<xfrm_ae_ftype_t, java.lang. @Unsigned Integer> {
    /**
     * {@code XFRM_AE_UNSPEC = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XFRM_AE_UNSPEC"
    )
    XFRM_AE_UNSPEC,

    /**
     * {@code XFRM_AE_RTHR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XFRM_AE_RTHR"
    )
    XFRM_AE_RTHR,

    /**
     * {@code XFRM_AE_RVAL = 2}
     */
    @EnumMember(
        value = 2L,
        name = "XFRM_AE_RVAL"
    )
    XFRM_AE_RVAL,

    /**
     * {@code XFRM_AE_LVAL = 4}
     */
    @EnumMember(
        value = 4L,
        name = "XFRM_AE_LVAL"
    )
    XFRM_AE_LVAL,

    /**
     * {@code XFRM_AE_ETHR = 8}
     */
    @EnumMember(
        value = 8L,
        name = "XFRM_AE_ETHR"
    )
    XFRM_AE_ETHR,

    /**
     * {@code XFRM_AE_CR = 16}
     */
    @EnumMember(
        value = 16L,
        name = "XFRM_AE_CR"
    )
    XFRM_AE_CR,

    /**
     * {@code XFRM_AE_CE = 32}
     */
    @EnumMember(
        value = 32L,
        name = "XFRM_AE_CE"
    )
    XFRM_AE_CE,

    /**
     * {@code XFRM_AE_CU = 64}
     */
    @EnumMember(
        value = 64L,
        name = "XFRM_AE_CU"
    )
    XFRM_AE_CU,

    /**
     * {@code __XFRM_AE_MAX = 65}
     */
    @EnumMember(
        value = 65L,
        name = "__XFRM_AE_MAX"
    )
    __XFRM_AE_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xfrm_nlgroups"
  )
  public enum xfrm_nlgroups implements Enum<xfrm_nlgroups>, TypedEnum<xfrm_nlgroups, java.lang. @Unsigned Integer> {
    /**
     * {@code XFRMNLGRP_NONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XFRMNLGRP_NONE"
    )
    XFRMNLGRP_NONE,

    /**
     * {@code XFRMNLGRP_ACQUIRE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XFRMNLGRP_ACQUIRE"
    )
    XFRMNLGRP_ACQUIRE,

    /**
     * {@code XFRMNLGRP_EXPIRE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "XFRMNLGRP_EXPIRE"
    )
    XFRMNLGRP_EXPIRE,

    /**
     * {@code XFRMNLGRP_SA = 3}
     */
    @EnumMember(
        value = 3L,
        name = "XFRMNLGRP_SA"
    )
    XFRMNLGRP_SA,

    /**
     * {@code XFRMNLGRP_POLICY = 4}
     */
    @EnumMember(
        value = 4L,
        name = "XFRMNLGRP_POLICY"
    )
    XFRMNLGRP_POLICY,

    /**
     * {@code XFRMNLGRP_AEVENTS = 5}
     */
    @EnumMember(
        value = 5L,
        name = "XFRMNLGRP_AEVENTS"
    )
    XFRMNLGRP_AEVENTS,

    /**
     * {@code XFRMNLGRP_REPORT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "XFRMNLGRP_REPORT"
    )
    XFRMNLGRP_REPORT,

    /**
     * {@code XFRMNLGRP_MIGRATE = 7}
     */
    @EnumMember(
        value = 7L,
        name = "XFRMNLGRP_MIGRATE"
    )
    XFRMNLGRP_MIGRATE,

    /**
     * {@code XFRMNLGRP_MAPPING = 8}
     */
    @EnumMember(
        value = 8L,
        name = "XFRMNLGRP_MAPPING"
    )
    XFRMNLGRP_MAPPING,

    /**
     * {@code __XFRMNLGRP_MAX = 9}
     */
    @EnumMember(
        value = 9L,
        name = "__XFRMNLGRP_MAX"
    )
    __XFRMNLGRP_MAX
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_kmaddress"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_kmaddress extends Struct {
    public xfrm_address_t local;

    public xfrm_address_t remote;

    public @Unsigned int reserved;

    public @Unsigned short family;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_migrate"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_migrate extends Struct {
    public xfrm_address_t old_daddr;

    public xfrm_address_t old_saddr;

    public xfrm_address_t new_daddr;

    public xfrm_address_t new_saddr;

    public char proto;

    public char mode;

    public @Unsigned short reserved;

    public @Unsigned int reqid;

    public @Unsigned short old_family;

    public @Unsigned short new_family;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_mgr"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_mgr extends Struct {
    public list_head list;

    public Ptr<?> notify;

    public Ptr<?> acquire;

    public Ptr<?> compile_policy;

    public Ptr<?> new_mapping;

    public Ptr<?> notify_policy;

    public Ptr<?> report;

    public Ptr<?> migrate;

    public Ptr<?> is_alive;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_translator"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_translator extends Struct {
    public Ptr<?> alloc_compat;

    public Ptr<?> rcv_msg_compat;

    public Ptr<?> xlate_user_policy_sockptr;

    public Ptr<module> owner;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_hash_state_ptrs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_hash_state_ptrs extends Struct {
    public Ptr<hlist_head> bydst;

    public Ptr<hlist_head> bysrc;

    public Ptr<hlist_head> byspi;

    public @Unsigned int hmask;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_skb_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_skb_cb extends Struct {
    public xfrm_tunnel_skb_cb header;

    public seq_of_xfrm_skb_cb seq;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_trans_tasklet"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_trans_tasklet extends Struct {
    public work_struct work;

    public @OriginalName("spinlock_t") spinlock queue_lock;

    public sk_buff_head queue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_trans_cb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_trans_cb extends Struct {
    public anon_member_of_ipfrag_skb_cb_and_header_of_anon_member_of_tcp_skb_cb_and_header_of_sock_exterr_skb header;

    public Ptr<?> finish;

    public Ptr<net> net;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xfrm_user_offload"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xfrm_user_offload extends Struct {
    public int ifindex;

    public char flags;
  }
}
