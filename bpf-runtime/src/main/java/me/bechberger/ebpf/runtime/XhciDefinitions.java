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
 * Generated class for BPF runtime types that start with xhci
 */
@java.lang.SuppressWarnings("unused")
public final class XhciDefinitions {
  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_abort_cmd_ring(Ptr<xhci_hcd> xhci, @Unsigned long flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_add_endpoint(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_add_ep_to_interval_table(Ptr<xhci_hcd> xhci, Ptr<xhci_bw_info> ep_bw,
      Ptr<xhci_interval_bw_table> bw_table, Ptr<usb_device> udev, Ptr<xhci_virt_ep> virt_ep,
      Ptr<xhci_tt_bw_info> tt_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_add_in_port(Ptr<xhci_hcd> xhci, @Unsigned int num_ports,
      Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> addr, int max_caps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_add_interrupter(Ptr<xhci_hcd> xhci, @Unsigned int intr_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_address_device(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      @Unsigned int timeout_ms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_align_td(Ptr<xhci_hcd> xhci, Ptr<urb> urb, @Unsigned int enqd_len,
      Ptr<java.lang. @Unsigned Integer> trb_buff_len, Ptr<xhci_segment> seg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_command> xhci_alloc_command(Ptr<xhci_hcd> xhci,
      boolean allocate_completion, @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_command> xhci_alloc_command_with_ctx(Ptr<xhci_hcd> xhci,
      boolean allocate_completion, @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_container_ctx> xhci_alloc_container_ctx(Ptr<xhci_hcd> xhci, int type,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_alloc_dbc($arg1, $arg2, (const struct dbc_driver*)$arg3)")
  public static Ptr<xhci_dbc> xhci_alloc_dbc(Ptr<device> dev, Ptr<?> base, Ptr<dbc_driver> driver) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_alloc_dev(Ptr<usb_hcd> hcd, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_interrupter> xhci_alloc_interrupter(Ptr<xhci_hcd> xhci, @Unsigned int segs,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_container_ctx> xhci_alloc_port_bw_ctx(Ptr<xhci_hcd> xhci,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_alloc_segments_for_ring(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_stream_info> xhci_alloc_stream_info(Ptr<xhci_hcd> xhci,
      @Unsigned int num_stream_ctxs, @Unsigned int num_streams, @Unsigned int max_packet,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_alloc_streams(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      Ptr<Ptr<usb_host_endpoint>> eps, @Unsigned int num_eps, @Unsigned int num_streams,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_alloc_tt_info(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev,
      Ptr<usb_device> hdev, Ptr<usb_tt> tt, @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_alloc_virt_device(Ptr<xhci_hcd> xhci, int slot_id, Ptr<usb_device> udev,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_bus_resume(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_bus_suspend(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short xhci_calculate_lpm_timeout(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      usb3_link_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_calculate_streams_and_bitmask(Ptr<xhci_hcd> xhci, Ptr<usb_device> udev,
      Ptr<Ptr<usb_host_endpoint>> eps, @Unsigned int num_eps,
      Ptr<java.lang. @Unsigned Integer> num_streams,
      Ptr<java.lang. @Unsigned Integer> changed_ep_bitmask) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short xhci_calculate_u1_timeout(Ptr<xhci_hcd> xhci, Ptr<usb_device> udev,
      Ptr<usb_endpoint_descriptor> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short xhci_calculate_u2_timeout(Ptr<xhci_hcd> xhci, Ptr<usb_device> udev,
      Ptr<usb_endpoint_descriptor> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_change_max_exit_latency(Ptr<xhci_hcd> xhci, Ptr<usb_device> udev,
      @Unsigned short max_exit_latency) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_check_args($arg1, $arg2, $arg3, $arg4, $arg5, (const u8*)$arg6)")
  public static int xhci_check_args(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      Ptr<usb_host_endpoint> ep, int check_ep, boolean check_virt_dev, String func) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_check_bandwidth(Ptr<usb_hcd> hcd, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_check_bw_drop_ep_streams(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> vdev,
      int i) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_check_bw_table(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev,
      int old_active_eps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_check_ep0_maxpacket(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> vdev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_cleanup_command_queue(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_clear_endpoint_bw_info(Ptr<xhci_bw_info> bw_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_clear_hub_tt_buffer(Ptr<xhci_hcd> xhci, Ptr<xhci_td> td,
      Ptr<xhci_virt_ep> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_clear_tt_buffer_complete(Ptr<usb_hcd> hcd, Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_configure_endpoint(Ptr<xhci_hcd> xhci, Ptr<usb_device> udev,
      Ptr<xhci_command> command, boolean ctx_change, boolean must_succeed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_context_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_copy_ep0_dequeue_into_input_ctx(Ptr<xhci_hcd> xhci,
      Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_create_dbc_dev(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_create_intel_xhci_sw_pdev(Ptr<xhci_hcd> xhci, @Unsigned int cap_offset) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_create_rhub_port_array(Ptr<xhci_hcd> xhci, Ptr<xhci_hub> rhub,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_interrupter> xhci_create_secondary_interrupter(Ptr<usb_hcd> hcd,
      @Unsigned int segs, @Unsigned int imod_interval, @Unsigned int intr_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_create_usb3x_bos_desc(Ptr<xhci_hcd> xhci, String buf,
      @Unsigned short wLength) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_dbc_alloc_requests($arg1, $arg2, $arg3, (void (*)(struct xhci_dbc*, struct dbc_request*))$arg4)")
  public static int xhci_dbc_alloc_requests(Ptr<xhci_dbc> dbc, @Unsigned int direction,
      Ptr<list_head> head, Ptr<?> fn) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static evtreturn xhci_dbc_do_handle_events(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_flush_endpoint_requests(Ptr<dbc_ep> dep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_giveback(Ptr<dbc_request> req, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_handle_events(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_init_ep_contexts(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_mem_cleanup(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_mem_init(Ptr<xhci_dbc> dbc,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_queue_bulk_tx(Ptr<dbc_ep> dep, Ptr<dbc_request> req) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_reinit_ep_rings(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_remove(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_resume(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_ring> xhci_dbc_ring_alloc(Ptr<device> dev, xhci_ring_type type,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_ring_init(Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_start(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_stop(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_suspend(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_tty_probe(Ptr<device> dev, Ptr<?> base, Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_dbc_tty_register_device(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_tty_remove(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_dbc_tty_unregister_device(Ptr<xhci_dbc> dbc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_dbg_trace($arg1, (void (*)(struct va_format*))$arg2, (const u8*)$arg3, $arg4_)")
  public static void xhci_dbg_trace(Ptr<xhci_hcd> xhci, Ptr<?> trace, String fmt,
      java.lang.Object... param3) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_create_endpoint(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> dev,
      int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_create_root() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_create_slot(Ptr<xhci_hcd> xhci, int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_create_stream_files(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> dev,
      int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_exit(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_debugfs_extcap_regset($arg1, $arg2, (const struct debugfs_reg32*)$arg3, $arg4, (const u8*)$arg5)")
  public static void xhci_debugfs_extcap_regset(Ptr<xhci_hcd> xhci, int cap_id,
      Ptr<debugfs_reg32> regs, @Unsigned long n, String cap_name) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_init(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_debugfs_regset($arg1, $arg2, (const struct debugfs_reg32*)$arg3, $arg4, $arg5, (const u8*)$arg6, $arg7_)")
  public static void xhci_debugfs_regset(Ptr<xhci_hcd> xhci, @Unsigned int base,
      Ptr<debugfs_reg32> regs, @Unsigned long nregs, Ptr<dentry> parent, String fmt,
      java.lang.Object... param6) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_remove_endpoint(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> dev,
      int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_remove_root() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_debugfs_remove_slot(Ptr<xhci_hcd> xhci, int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)xhci_decode_ctrl_ctx($arg1, $arg2, $arg3))")
  public static String xhci_decode_ctrl_ctx(String str, @Unsigned long drop, @Unsigned long add) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)xhci_decode_portsc($arg1, $arg2))")
  public static String xhci_decode_portsc(String str, @Unsigned int portsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("((const u8*)xhci_decode_usbsts($arg1, $arg2))")
  public static String xhci_decode_usbsts(String str, @Unsigned int usbsts) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_device_name_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_disable_and_free_slot(Ptr<xhci_hcd> xhci, @Unsigned int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_disable_hub_port_wake(Ptr<xhci_hcd> xhci, Ptr<xhci_hub> rhub,
      boolean do_wakeup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_disable_interrupter(Ptr<xhci_hcd> xhci, Ptr<xhci_interrupter> ir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_disable_slot(Ptr<xhci_hcd> xhci, @Unsigned int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_disable_usb3_lpm_timeout(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      usb3_link_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_discover_or_reset_device(Ptr<usb_hcd> hcd, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_ring> xhci_dma_to_transfer_ring(Ptr<xhci_virt_ep> ep,
      @Unsigned long address) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_drop_endpoint(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_drop_ep_from_interval_table(Ptr<xhci_hcd> xhci, Ptr<xhci_bw_info> ep_bw,
      Ptr<xhci_interval_bw_table> bw_table, Ptr<usb_device> udev, Ptr<xhci_virt_ep> virt_ep,
      Ptr<xhci_tt_bw_info> tt_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_enable_device(Ptr<usb_hcd> hcd, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_enable_interrupter(Ptr<xhci_interrupter> ir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_enable_usb3_lpm_timeout(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      usb3_link_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_endpoint_context_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_endpoint_copy(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> in_ctx,
      Ptr<xhci_container_ctx> out_ctx, @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_endpoint_disable(Ptr<usb_hcd> hcd, Ptr<usb_host_endpoint> host_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_endpoint_init(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev,
      Ptr<usb_device> udev, Ptr<usb_host_endpoint> ep,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_endpoint_reset(Ptr<usb_hcd> hcd, Ptr<usb_host_endpoint> host_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_endpoint_zero(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev,
      Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_enter_test_mode(Ptr<xhci_hcd> xhci, @Unsigned short test_mode,
      @Unsigned short wIndex, Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ext_cap_init(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_find_next_ext_cap(Ptr<?> base, @Unsigned int start, int id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_find_raw_port_number(Ptr<usb_hcd> hcd, int port1) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_command(Ptr<xhci_hcd> xhci, Ptr<xhci_command> command) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_container_ctx(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_dev(Ptr<usb_hcd> hcd, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_device_endpoint_resources(Ptr<xhci_hcd> xhci,
      Ptr<xhci_virt_device> virt_dev, boolean drop_control_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_endpoint_ring(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_host_resources(Ptr<xhci_hcd> xhci,
      Ptr<xhci_input_control_ctx> ctrl_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_interrupter(Ptr<xhci_hcd> xhci, Ptr<xhci_interrupter> ir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_port_bw_ctx(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_stream_ctx(Ptr<xhci_hcd> xhci, @Unsigned int num_stream_ctxs,
      Ptr<xhci_stream_ctx> stream_ctx, @Unsigned @OriginalName("dma_addr_t") long dma) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_stream_info(Ptr<xhci_hcd> xhci, Ptr<xhci_stream_info> stream_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_free_streams(Ptr<usb_hcd> hcd, Ptr<usb_device> udev,
      Ptr<Ptr<usb_host_endpoint>> eps, @Unsigned int num_eps,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_virt_device(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> dev,
      int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_free_virt_devices_depth_first(Ptr<xhci_hcd> xhci, int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_fs_bw_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_gen_setup(Ptr<usb_hcd> hcd,
      @OriginalName("xhci_get_quirks_t") Ptr<?> get_quirks) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_get_endpoint_index(Ptr<usb_endpoint_descriptor> desc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_ep_ctx> xhci_get_ep_ctx(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> ctx,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_get_frame(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_input_control_ctx> xhci_get_input_control_ctx(
      Ptr<xhci_container_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_get_isoc_frame_id(Ptr<xhci_hcd> xhci, Ptr<urb> urb, int index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_get_port_bandwidth(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> ctx,
      char dev_speed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_get_port_status(Ptr<usb_hcd> hcd, Ptr<xhci_bus_state> bus_state,
      @Unsigned short wIndex, @Unsigned int raw_port_status, Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned long xhci_get_resuming_ports(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_hub> xhci_get_rhub(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_slot_ctx> xhci_get_slot_ctx(Ptr<xhci_hcd> xhci,
      Ptr<xhci_container_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static String xhci_get_slot_state(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_get_ss_bw_consumed(Ptr<xhci_bw_info> ep_bw) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned short xhci_get_timeout_no_hub_lpm(Ptr<usb_device> udev,
      usb3_link_state state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_get_usb2_port_status(Ptr<xhci_port> port,
      Ptr<java.lang. @Unsigned Integer> status, @Unsigned int portsc,
      Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_get_usb3_port_status(Ptr<xhci_port> port,
      Ptr<java.lang. @Unsigned Integer> status, @Unsigned int portsc) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_virt_ep> xhci_get_virt_ep(Ptr<xhci_hcd> xhci, @Unsigned int slot_id,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_giveback_invalidated_tds(Ptr<xhci_virt_ep> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_halt(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_handle_command_timeout(Ptr<work_struct> work) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_handle_event_trb(Ptr<xhci_hcd> xhci, Ptr<xhci_interrupter> ir,
      Ptr<xhci_trb> event) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_handle_events(Ptr<xhci_hcd> xhci, Ptr<xhci_interrupter> ir,
      boolean skip_events) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_handle_halted_endpoint(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_ep> ep,
      Ptr<xhci_td> td, xhci_ep_reset_type reset_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_handle_stopped_cmd_ring(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cur_cmd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_handle_usb2_port_link_resume(Ptr<xhci_port> port, @Unsigned int portsc,
      Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_handshake(Ptr<?> ptr, @Unsigned int mask, @Unsigned int done,
      @Unsigned long timeout_us) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_hc_died(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_hcd_fini() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_hcd_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_hcd_init_usb3_data(Ptr<xhci_hcd> xhci, Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_hs_bw_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_hub_control(Ptr<usb_hcd> hcd, @Unsigned short typeReq,
      @Unsigned short wValue, @Unsigned short wIndex, String buf, @Unsigned short wLength) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_hub_status_data(Ptr<usb_hcd> hcd, String buf) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_init(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_init_driver($arg1, (const struct xhci_driver_overrides*)$arg2)")
  public static void xhci_init_driver(Ptr<hc_driver> drv, Ptr<xhci_driver_overrides> over) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_initialize_ring_info(Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_initialize_ring_segments(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_intel_unregister_pdev(Ptr<?> arg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_invalidate_cancelled_tds(Ptr<xhci_virt_ep> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn xhci_irq(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_is_vendor_info_code(Ptr<xhci_hcd> xhci, @Unsigned int trb_comp_code) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_kill_endpoint_urbs(Ptr<xhci_hcd> xhci, int slot_id, int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_kill_ring_urbs(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_last_valid_endpoint(@Unsigned int added_ctxs) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_map_temp_buffer(Ptr<usb_hcd> hcd, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_map_urb_for_dma(Ptr<usb_hcd> hcd, Ptr<urb> urb,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_mem_cleanup(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_mem_init(Ptr<xhci_hcd> xhci, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_microframes_to_exponent(Ptr<usb_device> udev,
      Ptr<usb_host_endpoint> ep, @Unsigned int desc_interval, @Unsigned int min_exponent,
      @Unsigned int max_exponent) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_move_dequeue_past_td(Ptr<xhci_hcd> xhci, @Unsigned int slot_id,
      @Unsigned int ep_index, @Unsigned int stream_id, Ptr<xhci_td> td) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @OriginalName("irqreturn_t") irqreturn xhci_msi_irq(int irq, Ptr<?> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_parse_exponent_interval(Ptr<usb_device> udev,
      Ptr<usb_host_endpoint> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_pci_common_probe($arg1, (const struct pci_device_id*)$arg2)")
  public static int xhci_pci_common_probe(Ptr<pci_dev> dev, Ptr<pci_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_pci_exit() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_pci_init() {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_pci_poweroff_late(Ptr<usb_hcd> hcd, boolean do_wakeup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_pci_probe($arg1, (const struct pci_device_id*)$arg2)")
  public static int xhci_pci_probe(Ptr<pci_dev> dev, Ptr<pci_device_id> id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_pci_quirks(Ptr<device> dev, Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_pci_remove(Ptr<pci_dev> dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_pci_resume(Ptr<usb_hcd> hcd,
      @OriginalName("pm_message_t") pm_message msg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_pci_run(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_pci_setup(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_pci_shutdown(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_pci_stop(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_pci_suspend(Ptr<usb_hcd> hcd, boolean do_wakeup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_pci_update_hub_device(Ptr<usb_hcd> hcd, Ptr<usb_device> hdev,
      Ptr<usb_tt> tt, @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static boolean xhci_pending_portevent(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_port_bw_show(Ptr<xhci_hcd> xhci, char dev_speed, Ptr<seq_file> s) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static usb_link_tunnel_mode xhci_port_is_tunneled(Ptr<xhci_hcd> xhci,
      Ptr<xhci_port> port) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_port_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_port_state_to_neutral(@Unsigned int state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_port_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long xhci_port_write(Ptr<file> file, String ubuf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_portsc_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_process_cancelled_tds(Ptr<xhci_virt_ep> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_address_device(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd,
      @Unsigned @OriginalName("dma_addr_t") long in_ctx_ptr, @Unsigned int slot_id,
      xhci_setup_dev setup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_bulk_tx(Ptr<xhci_hcd> xhci,
      @Unsigned @OriginalName("gfp_t") int mem_flags, Ptr<urb> urb, int slot_id,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_configure_endpoint(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd,
      @Unsigned @OriginalName("dma_addr_t") long in_ctx_ptr, @Unsigned int slot_id,
      boolean command_must_succeed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_ctrl_tx(Ptr<xhci_hcd> xhci,
      @Unsigned @OriginalName("gfp_t") int mem_flags, Ptr<urb> urb, int slot_id,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_evaluate_context(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd,
      @Unsigned @OriginalName("dma_addr_t") long in_ctx_ptr, @Unsigned int slot_id,
      boolean command_must_succeed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_get_port_bw(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd,
      @Unsigned @OriginalName("dma_addr_t") long in_ctx_ptr, char dev_speed,
      boolean command_must_succeed) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_intr_tx(Ptr<xhci_hcd> xhci,
      @Unsigned @OriginalName("gfp_t") int mem_flags, Ptr<urb> urb, int slot_id,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_isoc_tx(Ptr<xhci_hcd> xhci,
      @Unsigned @OriginalName("gfp_t") int mem_flags, Ptr<urb> urb, int slot_id,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_isoc_tx_prepare(Ptr<xhci_hcd> xhci,
      @Unsigned @OriginalName("gfp_t") int mem_flags, Ptr<urb> urb, int slot_id,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_reset_device(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd,
      @Unsigned int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_reset_ep(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd, int slot_id,
      @Unsigned int ep_index, xhci_ep_reset_type reset_type) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_slot_control(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd,
      @Unsigned int trb_type, @Unsigned int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_stop_endpoint(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd, int slot_id,
      @Unsigned int ep_index, int suspend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_queue_vendor_command(Ptr<xhci_hcd> xhci, Ptr<xhci_command> cmd,
      @Unsigned int field1, @Unsigned int field2, @Unsigned int field3, @Unsigned int field4) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_quiesce(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_remove_dbc_dev(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_remove_secondary_interrupter(Ptr<usb_hcd> hcd, Ptr<xhci_interrupter> ir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_reserve_bandwidth(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev,
      Ptr<xhci_container_ctx> in_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_reset(Ptr<xhci_hcd> xhci, @Unsigned long timeout_us) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_reset_bandwidth(Ptr<usb_hcd> hcd, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_resume(Ptr<xhci_hcd> xhci, boolean power_lost, boolean is_auto_resume) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_ring> xhci_ring_alloc(Ptr<xhci_hcd> xhci, @Unsigned int num_segs,
      xhci_ring_type type, @Unsigned int max_packet, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ring_cmd_db(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ring_cycle_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ring_dequeue_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ring_device(Ptr<xhci_hcd> xhci, int slot_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ring_doorbell_for_active_rings(Ptr<xhci_hcd> xhci, @Unsigned int slot_id,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ring_dump_segment(Ptr<seq_file> s, Ptr<xhci_segment> seg) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ring_enqueue_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ring_ep_doorbell(Ptr<xhci_hcd> xhci, @Unsigned int slot_id,
      @Unsigned int ep_index, @Unsigned int stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ring_expansion(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring,
      @Unsigned int num_new_segs, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ring_free(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ring_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ring_segments_free(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ring_trb_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_run(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_run_finished(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_segment> xhci_segment_alloc(Ptr<xhci_hcd> xhci, @Unsigned int max_packet,
      @Unsigned int num, @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_set_cmd_ring_deq(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_set_interrupter_moderation(Ptr<xhci_interrupter> ir,
      @Unsigned int imod_interval) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_set_link_state(Ptr<xhci_hcd> xhci, Ptr<xhci_port> port,
      @Unsigned int link_state) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_set_port_power(Ptr<xhci_hcd> xhci, Ptr<xhci_port> port, boolean on,
      Ptr<java.lang. @Unsigned Long> flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_set_usb2_hardware_lpm(Ptr<usb_hcd> hcd, Ptr<usb_device> udev, int enable) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_setup_addressable_virt_dev(Ptr<xhci_hcd> xhci, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_setup_device(Ptr<usb_hcd> hcd, Ptr<usb_device> udev, xhci_setup_dev setup,
      @Unsigned int timeout_ms) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_setup_no_streams_ep_input_ctx(Ptr<xhci_ep_ctx> ep_ctx,
      Ptr<xhci_virt_ep> ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_setup_port_arrays(Ptr<xhci_hcd> xhci,
      @Unsigned @OriginalName("gfp_t") int flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_setup_streams_ep_input_ctx(Ptr<xhci_hcd> xhci, Ptr<xhci_ep_ctx> ep_ctx,
      Ptr<xhci_stream_info> stream_info) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_shutdown(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_sideband_add_endpoint(Ptr<xhci_sideband> sb,
      Ptr<usb_host_endpoint> host_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_sideband_create_interrupter(Ptr<xhci_sideband> sb, int num_seg,
      boolean ip_autoclear, @Unsigned int imod_interval, int intr_num) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> xhci_sideband_get_endpoint_buffer(Ptr<xhci_sideband> sb,
      Ptr<usb_host_endpoint> host_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<sg_table> xhci_sideband_get_event_buffer(Ptr<xhci_sideband> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_sideband_interrupter_id(Ptr<xhci_sideband> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_sideband_notify_ep_ring_free(Ptr<xhci_sideband> sb,
      @Unsigned int ep_index) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_sideband_register($arg1, $arg2, (int (*)(struct usb_interface*, struct xhci_sideband_event*))$arg3)")
  public static Ptr<xhci_sideband> xhci_sideband_register(Ptr<usb_interface> intf,
      xhci_sideband_type type, Ptr<?> notify_client) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_sideband_remove_endpoint(Ptr<xhci_sideband> sb,
      Ptr<usb_host_endpoint> host_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_sideband_remove_interrupter(Ptr<xhci_sideband> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_sideband_stop_endpoint(Ptr<xhci_sideband> sb,
      Ptr<usb_host_endpoint> host_ep) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_sideband_unregister(Ptr<xhci_sideband> sb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_skip_sec_intr_events(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring,
      Ptr<xhci_interrupter> ir) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_slot_context_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_slot_copy(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> in_ctx,
      Ptr<xhci_container_ctx> out_ctx) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_ss_bw_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_ssic_port_unused_quirk(Ptr<usb_hcd> hcd, boolean suspend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_start(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_stop(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_stop_device(Ptr<xhci_hcd> xhci, int slot_id, int suspend) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_stop_endpoint_sync(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_ep> ep, int suspend,
      @Unsigned @OriginalName("gfp_t") int gfp_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_stream_context_array_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_stream_context_array_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_stream_id_open(Ptr<inode> inode, Ptr<file> file) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_stream_id_show(Ptr<seq_file> s, Ptr<?> unused) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction("xhci_stream_id_write($arg1, (const u8*)$arg2, $arg3, $arg4)")
  public static @OriginalName("ssize_t") long xhci_stream_id_write(Ptr<file> file, String ubuf,
      @Unsigned long count, Ptr<java.lang. @OriginalName("loff_t") Long> ppos) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_suspend(Ptr<xhci_hcd> xhci, boolean do_wakeup) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_td_cleanup(Ptr<xhci_hcd> xhci, Ptr<xhci_td> td, Ptr<xhci_ring> ep_ring,
      int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned int xhci_td_remainder(Ptr<xhci_hcd> xhci, int transferred,
      int trb_buff_len, @Unsigned int td_total_len, Ptr<urb> urb, boolean more_trbs_coming) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_test_and_clear_bit(Ptr<xhci_hcd> xhci, Ptr<xhci_port> port,
      @Unsigned int port_bit) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static @Unsigned @OriginalName("dma_addr_t") long xhci_trb_virt_to_dma(
      Ptr<xhci_segment> seg, Ptr<xhci_trb> trb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_ring> xhci_triad_to_transfer_ring(Ptr<xhci_hcd> xhci,
      @Unsigned int slot_id, @Unsigned int ep_index, @Unsigned int stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_try_enable_msi(Ptr<usb_hcd> hcd) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_unmap_td_bounce_buffer(Ptr<xhci_hcd> xhci, Ptr<xhci_ring> ring,
      Ptr<xhci_td> td) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_unmap_urb_for_dma(Ptr<usb_hcd> hcd, Ptr<urb> urb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_update_bw_info(Ptr<xhci_hcd> xhci, Ptr<xhci_container_ctx> in_ctx,
      Ptr<xhci_input_control_ctx> ctrl_ctx, Ptr<xhci_virt_device> virt_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_update_device(Ptr<usb_hcd> hcd, Ptr<usb_device> udev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_update_erst_dequeue(Ptr<xhci_hcd> xhci, Ptr<xhci_interrupter> ir,
      boolean clear_ehb) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_update_hub_device(Ptr<usb_hcd> hcd, Ptr<usb_device> hdev, Ptr<usb_tt> tt,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_update_stream_segment_mapping(Ptr<xarray> trb_address_map,
      Ptr<xhci_ring> ring, Ptr<xhci_segment> first_seg,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_update_tt_active_eps(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev,
      int old_active_eps) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_urb_dequeue(Ptr<usb_hcd> hcd, Ptr<urb> urb, int status) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static int xhci_urb_enqueue(Ptr<usb_hcd> hcd, Ptr<urb> urb,
      @Unsigned @OriginalName("gfp_t") int mem_flags) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_urb_free_priv(Ptr<urb_priv> urb_priv) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static Ptr<xhci_ring> xhci_virt_ep_to_ring(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_ep> ep,
      @Unsigned int stream_id) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_zero_64b_regs(Ptr<xhci_hcd> xhci) {
    throw new MethodIsBPFRelatedFunction();
  }

  @NotUsableInJava
  @BuiltinBPFFunction
  public static void xhci_zero_in_ctx(Ptr<xhci_hcd> xhci, Ptr<xhci_virt_device> virt_dev) {
    throw new MethodIsBPFRelatedFunction();
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xhci_sideband_type"
  )
  public enum xhci_sideband_type implements Enum<xhci_sideband_type>, TypedEnum<xhci_sideband_type, java.lang. @Unsigned Integer> {
    /**
     * {@code XHCI_SIDEBAND_AUDIO = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XHCI_SIDEBAND_AUDIO"
    )
    XHCI_SIDEBAND_AUDIO,

    /**
     * {@code XHCI_SIDEBAND_VENDOR = 1}
     */
    @EnumMember(
        value = 1L,
        name = "XHCI_SIDEBAND_VENDOR"
    )
    XHCI_SIDEBAND_VENDOR
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xhci_sideband_notify_type"
  )
  public enum xhci_sideband_notify_type implements Enum<xhci_sideband_notify_type>, TypedEnum<xhci_sideband_notify_type, java.lang. @Unsigned Integer> {
    /**
     * {@code XHCI_SIDEBAND_XFER_RING_FREE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "XHCI_SIDEBAND_XFER_RING_FREE"
    )
    XHCI_SIDEBAND_XFER_RING_FREE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_sideband_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_sideband_event extends Struct {
    public xhci_sideband_notify_type type;

    public Ptr<?> evt_data;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_sideband"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_sideband extends Struct {
    public Ptr<xhci_hcd> xhci;

    public Ptr<xhci_virt_device> vdev;

    public Ptr<xhci_virt_ep> @Size(31) [] eps;

    public Ptr<xhci_interrupter> ir;

    public xhci_sideband_type type;

    public mutex mutex;

    public Ptr<usb_interface> intf;

    public Ptr<?> notify_client;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_hcd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_hcd extends Struct {
    public Ptr<usb_hcd> main_hcd;

    public Ptr<usb_hcd> shared_hcd;

    public Ptr<xhci_cap_regs> cap_regs;

    public Ptr<xhci_op_regs> op_regs;

    public Ptr<xhci_run_regs> run_regs;

    public Ptr<xhci_doorbell_array> dba;

    public @Unsigned int hcs_params1;

    public @Unsigned int hcs_params2;

    public @Unsigned int hcs_params3;

    public @Unsigned int hcc_params;

    public @Unsigned int hcc_params2;

    public @OriginalName("spinlock_t") spinlock lock;

    public @Unsigned short hci_version;

    public @Unsigned short max_interrupters;

    public @Unsigned int imod_interval;

    public @Unsigned int page_size;

    public int nvecs;

    public Ptr<clk> clk;

    public Ptr<clk> reg_clk;

    public Ptr<reset_control> reset;

    public Ptr<xhci_device_context_array> dcbaa;

    public Ptr<Ptr<xhci_interrupter>> interrupters;

    public Ptr<xhci_ring> cmd_ring;

    public @Unsigned int cmd_ring_state;

    public list_head cmd_list;

    public @Unsigned int cmd_ring_reserved_trbs;

    public delayed_work cmd_timer;

    public completion cmd_ring_stop_completion;

    public Ptr<xhci_command> current_cmd;

    public Ptr<xhci_scratchpad> scratchpad;

    public mutex mutex;

    public Ptr<xhci_virt_device> @Size(256) [] devs;

    public Ptr<xhci_root_port_bw_info> rh_bw;

    public Ptr<dma_pool> device_pool;

    public Ptr<dma_pool> segment_pool;

    public Ptr<dma_pool> small_streams_pool;

    public Ptr<dma_pool> port_bw_pool;

    public Ptr<dma_pool> medium_streams_pool;

    public @Unsigned int xhc_state;

    public @Unsigned long run_graceperiod;

    public s3_save s3;

    public @Unsigned long quirks;

    public @Unsigned int num_active_eps;

    public @Unsigned int limit_active_eps;

    public Ptr<xhci_port> hw_ports;

    public xhci_hub usb2_rhub;

    public xhci_hub usb3_rhub;

    public @Unsigned int hw_lpm_support;

    public @Unsigned int broken_suspend;

    public @Unsigned int allow_single_roothub;

    public Ptr<xhci_port_cap> port_caps;

    public @Unsigned int num_port_caps;

    public timer_list comp_mode_recovery_timer;

    public @Unsigned int port_status_u0;

    public @Unsigned short test_mode;

    public Ptr<dentry> debugfs_root;

    public Ptr<dentry> debugfs_slots;

    public list_head regset_list;

    public Ptr<?> dbc;

    public @Unsigned long @Size(0) [] priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_virt_device"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_virt_device extends Struct {
    public int slot_id;

    public Ptr<usb_device> udev;

    public Ptr<xhci_container_ctx> out_ctx;

    public Ptr<xhci_container_ctx> in_ctx;

    public xhci_virt_ep @Size(31) [] eps;

    public Ptr<xhci_port> rhub_port;

    public Ptr<xhci_interval_bw_table> bw_table;

    public Ptr<xhci_tt_bw_info> tt_info;

    public @Unsigned long flags;

    public @Unsigned short current_mel;

    public Ptr<?> debugfs_private;

    public Ptr<xhci_sideband> sideband;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_virt_ep"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_virt_ep extends Struct {
    public Ptr<xhci_virt_device> vdev;

    public @Unsigned int ep_index;

    public Ptr<xhci_ring> ring;

    public Ptr<xhci_stream_info> stream_info;

    public Ptr<xhci_ring> new_ring;

    public @Unsigned int err_count;

    public @Unsigned int ep_state;

    public list_head cancelled_td_list;

    public Ptr<xhci_hcd> xhci;

    public Ptr<xhci_segment> queued_deq_seg;

    public Ptr<xhci_trb> queued_deq_ptr;

    public boolean skip;

    public xhci_bw_info bw_info;

    public list_head bw_endpoint_list;

    public @Unsigned long stop_time;

    public int next_frame_id;

    public boolean use_extended_tbc;

    public Ptr<xhci_sideband> sideband;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_interrupter"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_interrupter extends Struct {
    public Ptr<xhci_ring> event_ring;

    public xhci_erst erst;

    public Ptr<xhci_intr_reg> ir_set;

    public @Unsigned int intr_num;

    public boolean ip_autoclear;

    public @Unsigned int isoc_bei_interval;

    public @Unsigned int s3_iman;

    public @Unsigned int s3_imod;

    public @Unsigned int s3_erst_size;

    public @Unsigned long s3_erst_base;

    public @Unsigned long s3_erst_dequeue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_cap_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_cap_regs extends Struct {
    public @Unsigned @OriginalName("__le32") int hc_capbase;

    public @Unsigned @OriginalName("__le32") int hcs_params1;

    public @Unsigned @OriginalName("__le32") int hcs_params2;

    public @Unsigned @OriginalName("__le32") int hcs_params3;

    public @Unsigned @OriginalName("__le32") int hcc_params;

    public @Unsigned @OriginalName("__le32") int db_off;

    public @Unsigned @OriginalName("__le32") int run_regs_off;

    public @Unsigned @OriginalName("__le32") int hcc_params2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_op_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_op_regs extends Struct {
    public @Unsigned @OriginalName("__le32") int command;

    public @Unsigned @OriginalName("__le32") int status;

    public @Unsigned @OriginalName("__le32") int page_size;

    public @Unsigned @OriginalName("__le32") int reserved1;

    public @Unsigned @OriginalName("__le32") int reserved2;

    public @Unsigned @OriginalName("__le32") int dev_notification;

    public @Unsigned @OriginalName("__le64") long cmd_ring;

    public @Unsigned @OriginalName("__le32") int @Size(4) [] reserved3;

    public @Unsigned @OriginalName("__le64") long dcbaa_ptr;

    public @Unsigned @OriginalName("__le32") int config_reg;

    public @Unsigned @OriginalName("__le32") int @Size(241) [] reserved4;

    public @Unsigned @OriginalName("__le32") int port_status_base;

    public @Unsigned @OriginalName("__le32") int port_power_base;

    public @Unsigned @OriginalName("__le32") int port_link_base;

    public @Unsigned @OriginalName("__le32") int reserved5;

    public @Unsigned @OriginalName("__le32") int @Size(1016) [] reserved6;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_intr_reg"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_intr_reg extends Struct {
    public @Unsigned @OriginalName("__le32") int iman;

    public @Unsigned @OriginalName("__le32") int imod;

    public @Unsigned @OriginalName("__le32") int erst_size;

    public @Unsigned @OriginalName("__le32") int rsvd;

    public @Unsigned @OriginalName("__le64") long erst_base;

    public @Unsigned @OriginalName("__le64") long erst_dequeue;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_run_regs"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_run_regs extends Struct {
    public @Unsigned @OriginalName("__le32") int microframe_index;

    public @Unsigned @OriginalName("__le32") int @Size(7) [] rsvd;

    public xhci_intr_reg @Size(128) [] ir_set;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_doorbell_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_doorbell_array extends Struct {
    public @Unsigned @OriginalName("__le32") int @Size(256) [] doorbell;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_container_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_container_ctx extends Struct {
    public @Unsigned int type;

    public int size;

    public Ptr<java.lang.Character> bytes;

    public @Unsigned @OriginalName("dma_addr_t") long dma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_slot_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_slot_ctx extends Struct {
    public @Unsigned @OriginalName("__le32") int dev_info;

    public @Unsigned @OriginalName("__le32") int dev_info2;

    public @Unsigned @OriginalName("__le32") int tt_info;

    public @Unsigned @OriginalName("__le32") int dev_state;

    public @Unsigned @OriginalName("__le32") int @Size(4) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_ep_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_ep_ctx extends Struct {
    public @Unsigned @OriginalName("__le32") int ep_info;

    public @Unsigned @OriginalName("__le32") int ep_info2;

    public @Unsigned @OriginalName("__le64") long deq;

    public @Unsigned @OriginalName("__le32") int tx_info;

    public @Unsigned @OriginalName("__le32") int @Size(3) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_input_control_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_input_control_ctx extends Struct {
    public @Unsigned @OriginalName("__le32") int drop_flags;

    public @Unsigned @OriginalName("__le32") int add_flags;

    public @Unsigned @OriginalName("__le32") int @Size(6) [] rsvd2;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_command"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_command extends Struct {
    public Ptr<xhci_container_ctx> in_ctx;

    public @Unsigned int status;

    public @Unsigned int comp_param;

    public int slot_id;

    public Ptr<completion> completion;

    public Ptr<xhci_trb> command_trb;

    public list_head cmd_list;

    public @Unsigned int timeout_ms;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "union xhci_trb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_trb extends Union {
    public xhci_link_trb link;

    public xhci_transfer_event trans_event;

    public xhci_event_cmd event_cmd;

    public xhci_generic_trb generic;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_stream_ctx"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_stream_ctx extends Struct {
    public @Unsigned @OriginalName("__le64") long stream_ring;

    public @Unsigned @OriginalName("__le32") int @Size(2) [] reserved;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_stream_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_stream_info extends Struct {
    public Ptr<Ptr<xhci_ring>> stream_rings;

    public @Unsigned int num_streams;

    public Ptr<xhci_stream_ctx> stream_ctx_array;

    public @Unsigned int num_stream_ctxs;

    public @Unsigned @OriginalName("dma_addr_t") long ctx_array_dma;

    public xarray trb_address_map;

    public Ptr<xhci_command> free_streams_command;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_ring"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_ring extends Struct {
    public Ptr<xhci_segment> first_seg;

    public Ptr<xhci_segment> last_seg;

    public Ptr<xhci_trb> enqueue;

    public Ptr<xhci_segment> enq_seg;

    public Ptr<xhci_trb> dequeue;

    public Ptr<xhci_segment> deq_seg;

    public list_head td_list;

    public @Unsigned int cycle_state;

    public @Unsigned int stream_id;

    public @Unsigned int num_segs;

    public @Unsigned int num_trbs_free;

    public @Unsigned int bounce_buf_len;

    public xhci_ring_type type;

    public @Unsigned int old_trb_comp_code;

    public Ptr<xarray> trb_address_map;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_bw_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_bw_info extends Struct {
    public @Unsigned int ep_interval;

    public @Unsigned int mult;

    public @Unsigned int num_packets;

    public @Unsigned int max_packet_size;

    public @Unsigned int max_esit_payload;

    public @Unsigned int type;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_segment"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_segment extends Struct {
    public Ptr<xhci_trb> trbs;

    public Ptr<xhci_segment> next;

    public @Unsigned int num;

    public @Unsigned @OriginalName("dma_addr_t") long dma;

    public @Unsigned @OriginalName("dma_addr_t") long bounce_dma;

    public Ptr<?> bounce_buf;

    public @Unsigned int bounce_offs;

    public @Unsigned int bounce_len;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xhci_overhead_type"
  )
  public enum xhci_overhead_type implements Enum<xhci_overhead_type>, TypedEnum<xhci_overhead_type, java.lang. @Unsigned Integer> {
    /**
     * {@code LS_OVERHEAD_TYPE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "LS_OVERHEAD_TYPE"
    )
    LS_OVERHEAD_TYPE,

    /**
     * {@code FS_OVERHEAD_TYPE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "FS_OVERHEAD_TYPE"
    )
    FS_OVERHEAD_TYPE,

    /**
     * {@code HS_OVERHEAD_TYPE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "HS_OVERHEAD_TYPE"
    )
    HS_OVERHEAD_TYPE
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_interval_bw"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_interval_bw extends Struct {
    public @Unsigned int num_packets;

    public list_head endpoints;

    public @Unsigned int @Size(3) [] overhead;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_interval_bw_table"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_interval_bw_table extends Struct {
    public @Unsigned int interval0_esit_payload;

    public xhci_interval_bw @Size(16) [] interval_bw;

    public @Unsigned int bw_used;

    public @Unsigned int ss_bw_in;

    public @Unsigned int ss_bw_out;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_port"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_port extends Struct {
    public Ptr<java.lang. @Unsigned @OriginalName("__le32") Integer> addr;

    public int hw_portnum;

    public int hcd_portnum;

    public Ptr<xhci_hub> rhub;

    public Ptr<xhci_port_cap> port_cap;

    public @Unsigned int lpm_incapable;

    public @Unsigned long resume_timestamp;

    public boolean rexit_active;

    public int slot_id;

    public completion rexit_done;

    public completion u3exit_done;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_tt_bw_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_tt_bw_info extends Struct {
    public list_head tt_list;

    public int slot_id;

    public int ttport;

    public xhci_interval_bw_table bw_table;

    public int active_eps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_root_port_bw_info"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_root_port_bw_info extends Struct {
    public list_head tts;

    public @Unsigned int num_active_tts;

    public xhci_interval_bw_table bw_table;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_device_context_array"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_device_context_array extends Struct {
    public @Unsigned @OriginalName("__le64") long @Size(256) [] dev_context_ptrs;

    public @Unsigned @OriginalName("dma_addr_t") long dma;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_transfer_event"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_transfer_event extends Struct {
    public @Unsigned @OriginalName("__le64") long buffer;

    public @Unsigned @OriginalName("__le32") int transfer_len;

    public @Unsigned @OriginalName("__le32") int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_link_trb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_link_trb extends Struct {
    public @Unsigned @OriginalName("__le64") long segment_ptr;

    public @Unsigned @OriginalName("__le32") int intr_target;

    public @Unsigned @OriginalName("__le32") int control;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_event_cmd"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_event_cmd extends Struct {
    public @Unsigned @OriginalName("__le64") long cmd_trb;

    public @Unsigned @OriginalName("__le32") int status;

    public @Unsigned @OriginalName("__le32") int flags;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xhci_setup_dev"
  )
  public enum xhci_setup_dev implements Enum<xhci_setup_dev>, TypedEnum<xhci_setup_dev, java.lang. @Unsigned Integer> {
    /**
     * {@code SETUP_CONTEXT_ONLY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "SETUP_CONTEXT_ONLY"
    )
    SETUP_CONTEXT_ONLY,

    /**
     * {@code SETUP_CONTEXT_ADDRESS = 1}
     */
    @EnumMember(
        value = 1L,
        name = "SETUP_CONTEXT_ADDRESS"
    )
    SETUP_CONTEXT_ADDRESS
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_generic_trb"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_generic_trb extends Struct {
    public @Unsigned @OriginalName("__le32") int @Size(4) [] field;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xhci_cancelled_td_status"
  )
  public enum xhci_cancelled_td_status implements Enum<xhci_cancelled_td_status>, TypedEnum<xhci_cancelled_td_status, java.lang. @Unsigned Integer> {
    /**
     * {@code TD_DIRTY = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TD_DIRTY"
    )
    TD_DIRTY,

    /**
     * {@code TD_HALTED = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TD_HALTED"
    )
    TD_HALTED,

    /**
     * {@code TD_CLEARING_CACHE = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TD_CLEARING_CACHE"
    )
    TD_CLEARING_CACHE,

    /**
     * {@code TD_CLEARING_CACHE_DEFERRED = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TD_CLEARING_CACHE_DEFERRED"
    )
    TD_CLEARING_CACHE_DEFERRED,

    /**
     * {@code TD_CLEARED = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TD_CLEARED"
    )
    TD_CLEARED
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_td"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_td extends Struct {
    public list_head td_list;

    public list_head cancelled_td_list;

    public int status;

    public xhci_cancelled_td_status cancel_status;

    public Ptr<urb> urb;

    public Ptr<xhci_segment> start_seg;

    public Ptr<xhci_trb> start_trb;

    public Ptr<xhci_segment> end_seg;

    public Ptr<xhci_trb> end_trb;

    public Ptr<xhci_segment> bounce_seg;

    public boolean urb_length_set;

    public boolean error_mid_td;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xhci_ring_type"
  )
  public enum xhci_ring_type implements Enum<xhci_ring_type>, TypedEnum<xhci_ring_type, java.lang. @Unsigned Integer> {
    /**
     * {@code TYPE_CTRL = 0}
     */
    @EnumMember(
        value = 0L,
        name = "TYPE_CTRL"
    )
    TYPE_CTRL,

    /**
     * {@code TYPE_ISOC = 1}
     */
    @EnumMember(
        value = 1L,
        name = "TYPE_ISOC"
    )
    TYPE_ISOC,

    /**
     * {@code TYPE_BULK = 2}
     */
    @EnumMember(
        value = 2L,
        name = "TYPE_BULK"
    )
    TYPE_BULK,

    /**
     * {@code TYPE_INTR = 3}
     */
    @EnumMember(
        value = 3L,
        name = "TYPE_INTR"
    )
    TYPE_INTR,

    /**
     * {@code TYPE_STREAM = 4}
     */
    @EnumMember(
        value = 4L,
        name = "TYPE_STREAM"
    )
    TYPE_STREAM,

    /**
     * {@code TYPE_COMMAND = 5}
     */
    @EnumMember(
        value = 5L,
        name = "TYPE_COMMAND"
    )
    TYPE_COMMAND,

    /**
     * {@code TYPE_EVENT = 6}
     */
    @EnumMember(
        value = 6L,
        name = "TYPE_EVENT"
    )
    TYPE_EVENT
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_erst_entry"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_erst_entry extends Struct {
    public @Unsigned @OriginalName("__le64") long seg_addr;

    public @Unsigned @OriginalName("__le32") int seg_size;

    public @Unsigned @OriginalName("__le32") int rsvd;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_erst"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_erst extends Struct {
    public Ptr<xhci_erst_entry> entries;

    public @Unsigned int num_entries;

    public @Unsigned @OriginalName("dma_addr_t") long erst_dma_addr;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_scratchpad"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_scratchpad extends Struct {
    public Ptr<java.lang. @Unsigned Long> sp_array;

    public @Unsigned @OriginalName("dma_addr_t") long sp_dma;

    public Ptr<Ptr<?>> sp_buffers;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_bus_state"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_bus_state extends Struct {
    public @Unsigned long bus_suspended;

    public @Unsigned long next_statechange;

    public @Unsigned int port_c_suspend;

    public @Unsigned int suspended_ports;

    public @Unsigned int port_remote_wakeup;

    public @Unsigned long resuming_ports;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_port_cap"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_port_cap extends Struct {
    public Ptr<java.lang. @Unsigned Integer> psi;

    public char psi_count;

    public char psi_uid_count;

    public char maj_rev;

    public char min_rev;

    public @Unsigned int protocol_caps;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_hub"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_hub extends Struct {
    public Ptr<Ptr<xhci_port>> ports;

    public @Unsigned int num_ports;

    public Ptr<usb_hcd> hcd;

    public xhci_bus_state bus_state;

    public char maj_rev;

    public char min_rev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_driver_overrides"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_driver_overrides extends Struct {
    public @Unsigned long extra_priv_size;

    public Ptr<?> reset;

    public Ptr<?> start;

    public Ptr<?> add_endpoint;

    public Ptr<?> drop_endpoint;

    public Ptr<?> check_bandwidth;

    public Ptr<?> reset_bandwidth;

    public Ptr<?> update_hub_device;

    public Ptr<?> hub_control;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum xhci_ep_reset_type"
  )
  public enum xhci_ep_reset_type implements Enum<xhci_ep_reset_type>, TypedEnum<xhci_ep_reset_type, java.lang. @Unsigned Integer> {
    /**
     * {@code EP_HARD_RESET = 0}
     */
    @EnumMember(
        value = 0L,
        name = "EP_HARD_RESET"
    )
    EP_HARD_RESET,

    /**
     * {@code EP_SOFT_RESET = 1}
     */
    @EnumMember(
        value = 1L,
        name = "EP_SOFT_RESET"
    )
    EP_SOFT_RESET
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_dbc"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_dbc extends Struct {
    public @OriginalName("spinlock_t") spinlock lock;

    public Ptr<device> dev;

    public Ptr<xhci_hcd> xhci;

    public Ptr<dbc_regs> regs;

    public Ptr<xhci_ring> ring_evt;

    public Ptr<xhci_ring> ring_in;

    public Ptr<xhci_ring> ring_out;

    public xhci_erst erst;

    public Ptr<xhci_container_ctx> ctx;

    public Ptr<dbc_str_descs> string;

    public @Unsigned @OriginalName("dma_addr_t") long string_dma;

    public @Unsigned long string_size;

    public @Unsigned short idVendor;

    public @Unsigned short idProduct;

    public @Unsigned short bcdDevice;

    public char bInterfaceProtocol;

    public dbc_state state;

    public delayed_work event_work;

    public @Unsigned int poll_interval;

    public @Unsigned long xfer_timestamp;

    public @Unsigned int resume_required;

    public dbc_ep @Size(2) [] eps;

    public Ptr<dbc_driver> driver;

    public Ptr<?> priv;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_regset"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_regset extends Struct {
    public char @Size(32) [] name;

    public debugfs_regset32 regset;

    public @Unsigned long nregs;

    public list_head list;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_file_map"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_file_map extends Struct {
    public String name;

    public Ptr<?> show;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_ep_priv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_ep_priv extends Struct {
    public char @Size(32) [] name;

    public Ptr<dentry> root;

    public Ptr<xhci_stream_info> stream_info;

    public Ptr<xhci_ring> show_ring;

    public @Unsigned int stream_id;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "struct xhci_slot_priv"
  )
  @me.bechberger.ebpf.annotations.KernelBTF
  @NotUsableInJava
  public static class xhci_slot_priv extends Struct {
    public char @Size(32) [] name;

    public Ptr<dentry> root;

    public Ptr<xhci_ep_priv> @Size(31) [] eps;

    public Ptr<xhci_virt_device> dev;
  }

  @Type(
      noCCodeGeneration = true,
      cType = "enum evtreturn"
  )
  public enum evtreturn implements Enum<evtreturn>, TypedEnum<evtreturn, java.lang.Integer> {
    /**
     * {@code EVT_ERR = -1}
     */
    @EnumMember(
        value = -1L,
        name = "EVT_ERR"
    )
    EVT_ERR,

    /**
     * {@code EVT_DONE = 0}
     */
    @EnumMember(
        value = 0L,
        name = "EVT_DONE"
    )
    EVT_DONE,

    /**
     * {@code EVT_XFER_DONE = 1}
     */
    @EnumMember(
        value = 1L,
        name = "EVT_XFER_DONE"
    )
    EVT_XFER_DONE,

    /**
     * {@code EVT_GSER = 2}
     */
    @EnumMember(
        value = 2L,
        name = "EVT_GSER"
    )
    EVT_GSER,

    /**
     * {@code EVT_DISC = 3}
     */
    @EnumMember(
        value = 3L,
        name = "EVT_DISC"
    )
    EVT_DISC
  }
}
